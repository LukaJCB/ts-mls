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
import { Credential, isDefaultCredential } from "../src/credential.js"
import { getCiphersuiteImpl } from "../src/crypto/getCiphersuiteImpl.js"
import { CiphersuiteName, getCiphersuiteFromName } from "../src/crypto/ciphersuite.js"
import { createCommit } from "../src/createCommit.js"
import { processPrivateMessage } from "../src/processMessages.js"
import { defaultProposalTypes } from "../src/defaultProposalType.js"
import { defaultCredentialTypes } from "../src/defaultCredentialType.js"
import { LeafNode } from "../src/leafNode.js"
import { wireformats } from "../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../src/authenticationService.js"

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

  const alice = await generateKeyPackage({
    credential: aliceCredential,
    cipherSuite: impl,
  })
  const bob = await generateKeyPackage({
    credential: bobCredential,
    cipherSuite: impl,
  })
  const charlie = await generateKeyPackage({
    credential: charlieCredential,
    cipherSuite: impl,
  })

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const addBobProposal: ProposalAdd = { proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }
  const addBobCommitResult = await createCommit({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [addBobProposal],
  })
  aliceGroup = addBobCommitResult.newState
  let bobGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: addBobCommitResult.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  const addCharlieProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: charlie.publicPackage },
  }
  const addCharlieCommitResult = await createCommit({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [addCharlieProposal],
  })
  aliceGroup = addCharlieCommitResult.newState
  if (addCharlieCommitResult.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")
  const processAddCharlieResult = await processPrivateMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      pskIndex: makePskIndex(bobGroup, {}),
    },
    state: bobGroup,
    privateMessage: addCharlieCommitResult.commit.privateMessage,
  })
  bobGroup = processAddCharlieResult.newState
  const charlieGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: addCharlieCommitResult.welcome!.welcome,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

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
