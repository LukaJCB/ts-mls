import { createGroup, validateRatchetTree } from "../../src/clientState.js"
import { generateKeyPackage, generateKeyPackageWithKey } from "../../src/keyPackage.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { CryptoVerificationError, ValidationError } from "../../src/mlsError.js"
import { encodeRatchetTree, RatchetTree, addLeafNode } from "../../src/ratchetTree.js"
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
import { treeHashRoot } from "../../src/treeHash.js"
import { ProtocolVersionName } from "../../src/protocolVersion.js"

test.concurrent.each(Object.keys(ciphersuites))("should validate ratchet tree %s", async (cs) => {
  await testStructuralIntegrity(cs as CiphersuiteName)
  await testInvalidParentHash(cs as CiphersuiteName)
  await testInvalidTreeHash(cs as CiphersuiteName)
  await testDuplicatePublicKeys(cs as CiphersuiteName)
  await testInvalidLeafNodeSignature(cs as CiphersuiteName)
  await testInvalidLeafNodeSignatureKeyPackage(cs as CiphersuiteName)
  await testInvalidKeyPackageSignature(cs as CiphersuiteName)
  await testInvalidCipherSuite(cs as CiphersuiteName)
  await testInvalidMlsVersion(cs as CiphersuiteName)
  await testInvalidCredential(cs as CiphersuiteName)
  await testHpkeAndSignatureNotUnique(cs as CiphersuiteName)
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

  // flip a byte in the tree hash to invalidate it
  tree[0]!.leaf.parentHash[0] = (tree[0]!.leaf.parentHash[0]! + 1) & 0xff

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new CryptoVerificationError("Unable to verify parent hash"))
}

async function testDuplicatePublicKeys(cipherSuite: CiphersuiteName) {
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

  //modify alice's public key
  const tree = ratchetTreeFromExtension(groupInfo)!

  if (tree[0]!.nodeType === "parent") throw new Error("expected leaf")

  tree[0]!.leaf.hpkePublicKey = bob.publicPackage.leafNode.hpkePublicKey

  if (tree[2]!.nodeType === "parent") throw new Error("expected leaf")

  tree[2]!.leaf.hpkePublicKey = bob.publicPackage.leafNode.hpkePublicKey

  const treeExtension = groupInfo.extensions.find((ex) => ex.extensionType === "ratchet_tree")

  treeExtension!.extensionData = encodeRatchetTree(tree)

  groupInfo.groupContext.treeHash = await treeHashRoot(tree, impl.hash)

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new ValidationError("Multiple public keys with the same value"))
}

async function testInvalidLeafNodeSignature(cipherSuite: CiphersuiteName) {
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

  //tamper with a leaf node signature
  const tree = ratchetTreeFromExtension(groupInfo)!

  if (tree[0] === undefined || tree[0]!.nodeType === "parent") throw new Error("expected leaf")

  // flip a byte in the signature to invalidate it
  tree[0]!.leaf.signature[0] = (tree[0]!.leaf.signature[0]! + 1) & 0xff

  const treeExtension = groupInfo.extensions.find((ex) => ex.extensionType === "ratchet_tree")

  treeExtension!.extensionData = encodeRatchetTree(tree)

  groupInfo.groupContext.treeHash = await treeHashRoot(tree, impl.hash)

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new CryptoVerificationError("Could not verify leaf node signature"))
}

async function testInvalidLeafNodeSignatureKeyPackage(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)

  // tamper with the key_package leaf node signature
  const tree = ratchetTreeFromExtension(groupInfo)!

  if (tree[0] === undefined || tree[0]!.nodeType === "parent" || tree[0].leaf.leafNodeSource !== "key_package")
    throw new Error("expected key_package leaf source")

  // flip a byte in the signature to invalidate it
  tree[0]!.leaf.signature[0] = (tree[0]!.leaf.signature[0]! + 1) & 0xff

  const treeExtension = groupInfo.extensions.find((ex) => ex.extensionType === "ratchet_tree")

  treeExtension!.extensionData = encodeRatchetTree(tree)

  groupInfo.groupContext.treeHash = await treeHashRoot(tree, impl.hash)

  await expect(joinGroupExternal(groupInfo, bob.publicPackage, bob.privatePackage, false, impl)).rejects.toThrow(
    new CryptoVerificationError("Could not verify leaf node signature"),
  )
}

async function testInvalidKeyPackageSignature(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  // create an add proposal with a tampered keypackage signature
  bob.publicPackage.signature[0] = (bob.publicPackage.signature[0]! + 1) & 0xff

  const addBobProposal: Proposal = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [addBobProposal],
      },
    ),
  ).rejects.toThrow(new CryptoVerificationError("Invalid keypackage signature"))
}

async function testInvalidCipherSuite(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  // tamper with the KeyPackage cipherSuite string to mismatch the group's cipher suite
  bob.publicPackage.cipherSuite = "bogus-cipher" as CiphersuiteName

  const addBobProposal: Proposal = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [addBobProposal],
      },
    ),
  ).rejects.toThrow(new ValidationError("Invalid CipherSuite"))
}

async function testInvalidMlsVersion(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  // tamper with the KeyPackage version string to mismatch the group's version
  bob.publicPackage.version = "bogus-version" as ProtocolVersionName

  const addBobProposal: Proposal = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [addBobProposal],
      },
    ),
  ).rejects.toThrow(new ValidationError("Invalid mls version"))
}

async function testInvalidCredential(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

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

  const tree = ratchetTreeFromExtension(groupInfo)!

  // create an auth service that rejects all credentials
  const badAuthService = {
    async validateCredential(_c: Credential, _k: Uint8Array) {
      return false
    },
  }

  const err = await validateRatchetTree(
    tree,
    groupInfo.groupContext,
    defaultLifetimeConfig,
    badAuthService,
    groupInfo.groupContext.treeHash,
    impl,
  )

  expect(err).toBeInstanceOf(ValidationError)
  expect(err?.message).toBe("Could not validate credential")
}

async function testHpkeAndSignatureNotUnique(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const sigKeys = await impl.signature.keygen()

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackageWithKey(
    aliceCredential,
    defaultCapabilities(),
    defaultLifetime,
    [],
    sigKeys,
    impl,
  )

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackageWithKey(bobCredential, defaultCapabilities(), defaultLifetime, [], sigKeys, impl)

  const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)
  const tree = ratchetTreeFromExtension(groupInfo)!

  // manually add bob with same signature key
  const [newTree] = addLeafNode(tree, bob.publicPackage.leafNode)

  const treeExtension = groupInfo.extensions.find((ex) => ex.extensionType === "ratchet_tree")
  treeExtension!.extensionData = encodeRatchetTree(newTree)

  groupInfo.groupContext.treeHash = await treeHashRoot(newTree, impl.hash)

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new ValidationError("hpke or signature keys not unique"))
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

  // flip a byte in the tree hash to invalidate it
  groupInfo.groupContext.treeHash[0] = (groupInfo.groupContext.treeHash[0]! + 1) & 0xff

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new ValidationError("Unable to verify tree hash"))
}
