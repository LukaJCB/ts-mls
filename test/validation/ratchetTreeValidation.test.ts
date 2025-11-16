import { createGroup, validateRatchetTree } from "../../src/clientState.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { CryptoVerificationError, ValidationError } from "../../src/mlsError.js"
import { RatchetTree } from "../../src/ratchetTree.js"
import { GroupContext } from "../../src/groupContext.js"
import { defaultLifetimeConfig } from "../../src/lifetimeConfig.js"
import { defaultAuthenticationService } from "../../src/authenticationService.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { Proposal } from "../../src/proposal.js"
import {
  createCommit,
  createGroupInfoWithExternalPubAndRatchetTree,
  joinGroupExternal,
} from "../../src/createCommit.js"
import { ratchetTreeFromExtension } from "../../src/groupInfo.js"

test.concurrent.each(Object.keys(ciphersuites))("should validate ratchet tree %s", async (cs) => {
  await testStructuralIntegrity(cs as CiphersuiteName)
  await testInvalidParentHash(cs as CiphersuiteName)
  await testInvalidTreeHash(cs as CiphersuiteName)
})

async function testStructuralIntegrity(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))
  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }

  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const validLeafNode = alice.publicPackage.leafNode
  // Make the first node a parent node, which is invalid for a leaf position
  const invalidTree: RatchetTree = [
    {
      nodeType: "parent",
      parent: {
        unmergedLeaves: [],
        parentHash: new Uint8Array(),
        hpkePublicKey: new Uint8Array(),
      },
    },
    { nodeType: "leaf", leaf: validLeafNode },
    { nodeType: "leaf", leaf: validLeafNode },
  ]

  const groupContext: GroupContext = {
    version: "mls10",
    cipherSuite: cipherSuite,
    epoch: 0n,
    treeHash: new Uint8Array(),
    groupId: new Uint8Array(),
    extensions: [],
    confirmedTranscriptHash: new Uint8Array(),
  }

  const error = await validateRatchetTree(
    invalidTree,
    groupContext,
    defaultLifetimeConfig,
    defaultAuthenticationService,
    new Uint8Array(),
    impl,
  )

  expect(error).toBeInstanceOf(ValidationError)
  expect(error?.message).toBe("Received Ratchet Tree is not structurally sound")
}

async function testInvalidParentHash(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: Proposal = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    {
      extraProposals: [addBobProposal],
    },
  )

  aliceGroup = addBobCommitResult.newState

  const emptyCommitResult = await createCommit({
    state: aliceGroup,
    cipherSuite: impl,
  })

  aliceGroup = emptyCommitResult.newState

  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)

  //modify parent hash
  const tree = ratchetTreeFromExtension(groupInfo)!

  if (tree[0]!.nodeType === "parent" || tree[0]!.leaf.leafNodeSource !== "commit") throw new Error("expected leaf")

  tree[0]!.leaf.parentHash[0] = 0
  tree[0]!.leaf.parentHash[1] = 0
  tree[0]!.leaf.parentHash[2] = 0
  tree[0]!.leaf.parentHash[3] = 0

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new CryptoVerificationError("Unable to verify parent hash"))
}

async function testInvalidTreeHash(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: Proposal = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    {
      extraProposals: [addBobProposal],
    },
  )

  aliceGroup = addBobCommitResult.newState

  const emptyCommitResult = await createCommit({
    state: aliceGroup,
    cipherSuite: impl,
  })

  aliceGroup = emptyCommitResult.newState

  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)

  //modify tree hash
  groupInfo.groupContext.treeHash[0] = 0
  groupInfo.groupContext.treeHash[1] = 0
  groupInfo.groupContext.treeHash[2] = 0
  groupInfo.groupContext.treeHash[3] = 0

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new ValidationError("Unable to verify tree hash"))
}
