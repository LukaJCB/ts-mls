import {
  createGroup,
  joinGroup,
  getOwnLeafNode,
  extractFromGroupMembers,
  getGroupMembers,
  getOwnSignatureKeyPair,
  getLeafNodeAt,
} from "../src/clientState.js"
import { generateKeyPackage } from "../src/keyPackage.js"
import { ProposalAdd } from "../src/proposal.js"
import { Credential, isDefaultCredential } from "../src/credential.js"
import { getCiphersuiteImpl } from "../src/crypto/getCiphersuiteImpl.js"
import { CiphersuiteName } from "../src/crypto/ciphersuite.js"
import { createCommit } from "../src/createCommit.js"
import { defaultProposalTypes } from "../src/defaultProposalType.js"
import { defaultCredentialTypes } from "../src/defaultCredentialType.js"
import { LeafNode } from "../src/leafNode.js"
import { wireformats } from "../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../src/authenticationService.js"
import { processMessageEnsureNoMutation } from "./scenario/common.js"
import { UsageError } from "../src/mlsError.js"

const SUITE: CiphersuiteName = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"

async function buildThreeMemberGroup() {
  const impl = await getCiphersuiteImpl(SUITE)

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
  const processAddCharlieResult = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    message: addCharlieCommitResult.commit,
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
  test("getOwnSignatureKeyPair returns the correct member for each client", async () => {
    const { aliceGroup, bobGroup, charlieGroup } = await buildThreeMemberGroup()

    const aliceLeaf = getOwnLeafNode(aliceGroup)
    const bobLeaf = getOwnLeafNode(bobGroup)
    const charlieLeaf = getOwnLeafNode(charlieGroup)

    expect(identityOf(aliceLeaf)).toBe("alice")
    expect(getOwnSignatureKeyPair(aliceGroup).publicKey).toStrictEqual(aliceLeaf.signaturePublicKey)
    expect(identityOf(bobLeaf)).toBe("bob")
    expect(getOwnSignatureKeyPair(bobGroup).publicKey).toStrictEqual(bobLeaf.signaturePublicKey)
    expect(identityOf(charlieLeaf)).toBe("charlie")
    expect(getOwnSignatureKeyPair(charlieGroup).publicKey).toStrictEqual(charlieLeaf.signaturePublicKey)
  })

  test("getLeafNodeAt returns the correct member for each client", async () => {
    const { aliceGroup, bobGroup, charlieGroup } = await buildThreeMemberGroup()

    const alicePk = getOwnSignatureKeyPair(aliceGroup).publicKey
    const bobPk = getOwnSignatureKeyPair(bobGroup).publicKey
    const charliePk = getOwnSignatureKeyPair(charlieGroup).publicKey

    expect(alicePk).toStrictEqual(getLeafNodeAt(aliceGroup, 0).signaturePublicKey)
    expect(alicePk).toStrictEqual(getLeafNodeAt(bobGroup, 0).signaturePublicKey)
    expect(alicePk).toStrictEqual(getLeafNodeAt(charlieGroup, 0).signaturePublicKey)

    expect(bobPk).toStrictEqual(getLeafNodeAt(aliceGroup, 1).signaturePublicKey)
    expect(bobPk).toStrictEqual(getLeafNodeAt(bobGroup, 1).signaturePublicKey)
    expect(bobPk).toStrictEqual(getLeafNodeAt(charlieGroup, 1).signaturePublicKey)

    expect(charliePk).toStrictEqual(getLeafNodeAt(aliceGroup, 2).signaturePublicKey)
    expect(charliePk).toStrictEqual(getLeafNodeAt(bobGroup, 2).signaturePublicKey)
    expect(charliePk).toStrictEqual(getLeafNodeAt(charlieGroup, 2).signaturePublicKey)
  })

  test("getLeafNodeAt should throw UsageError when out of bounds", async () => {
    const { aliceGroup } = await buildThreeMemberGroup()

    expect(() => {
      getLeafNodeAt(aliceGroup, 3)
    }).toThrow(new UsageError("No leaf at given leafIndex"))
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
