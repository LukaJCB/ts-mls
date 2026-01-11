import {
  createGroup,
  joinGroup,
  makePskIndex,
  getOwnLeafNode,
  extractFromGroupMembers,
  getGroupMembers,
} from "../src/clientState.js"
import { generateKeyPackage } from "../src/keyPackage.js"
import { ProposalAdd } from "../src/proposal.js"
import { defaultCapabilities } from "../src/defaultCapabilities.js"
import { defaultLifetime } from "../src/lifetime.js"
import { emptyPskIndex } from "../src/pskIndex.js"
import { Credential, isDefaultCredential } from "../src/credential.js"
import { getCiphersuiteImpl } from "../src/crypto/getCiphersuiteImpl.js"
import { CiphersuiteName, getCiphersuiteFromName } from "../src/crypto/ciphersuite.js"
import { createCommit } from "../src/createCommit.js"
import { processPrivateMessage } from "../src/processMessages.js"
import { defaultProposalTypes } from "../src/defaultProposalType.js"
import { defaultCredentialTypes } from "../src/credentialType.js"
import { LeafNode } from "../src/leafNode.js"

const SUITE: CiphersuiteName = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"

async function buildThreeMemberGroup() {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(SUITE))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }

  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const addBobProposal: ProposalAdd = { proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }
  const addBobCommitResult = await createCommit(
    { state: aliceGroup, cipherSuite: impl },
    { extraProposals: [addBobProposal] },
  )
  aliceGroup = addBobCommitResult.newState
  let bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  const addCharlieProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: charlie.publicPackage },
  }
  const addCharlieCommitResult = await createCommit(
    { state: aliceGroup, cipherSuite: impl },
    { extraProposals: [addCharlieProposal] },
  )
  aliceGroup = addCharlieCommitResult.newState
  if (addCharlieCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")
  const processAddCharlieResult = await processPrivateMessage(
    bobGroup,
    addCharlieCommitResult.commit.privateMessage,
    makePskIndex(bobGroup, {}),
    impl,
  )
  bobGroup = processAddCharlieResult.newState
  const charlieGroup = await joinGroup(
    addCharlieCommitResult.welcome!,
    charlie.publicPackage,
    charlie.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  return { aliceGroup, bobGroup, charlieGroup }
}

function identityOf(l: LeafNode): string {
  const c = l.credential
  if (!isDefaultCredential(c) || c.credentialType !== defaultCredentialTypes.basic)
    throw new Error("Expected basic credential in test")
  return new TextDecoder().decode(c.identity)
}

describe("clientState helpers", () => {
  test("getOwnLeafNode returns the correct member for each client", async () => {
    const { aliceGroup, bobGroup, charlieGroup } = await buildThreeMemberGroup()

    const aliceLeaf = getOwnLeafNode(aliceGroup)
    const bobLeaf = getOwnLeafNode(bobGroup)
    const charlieLeaf = getOwnLeafNode(charlieGroup)

    expect(identityOf(aliceLeaf)).toBe("alice")
    expect(identityOf(bobLeaf)).toBe("bob")
    expect(identityOf(charlieLeaf)).toBe("charlie")
  })

  test("extractFromGroupMembers maps identities and supports exclusion", async () => {
    const { aliceGroup } = await buildThreeMemberGroup()

    const allIds = extractFromGroupMembers(
      aliceGroup,
      () => false,
      (l) => identityOf(l),
    )
    expect(allIds.sort()).toEqual(["alice", "bob", "charlie"].sort())

    const noBob = extractFromGroupMembers(
      aliceGroup,
      (l) => identityOf(l) === "bob",
      (l) => identityOf(l),
    )
    expect(noBob.sort()).toEqual(["alice", "charlie"].sort())
  })

  test("getGroupMembers returns all members as LeafNodes", async () => {
    const { aliceGroup } = await buildThreeMemberGroup()

    const members = getGroupMembers(aliceGroup)
    const ids = members.map(identityOf).sort()
    expect(ids).toEqual(["alice", "bob", "charlie"].sort())
  })
})
