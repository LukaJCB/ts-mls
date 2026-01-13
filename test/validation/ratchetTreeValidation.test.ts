import { createGroup, validateRatchetTree } from "../../src/clientState.js"
import { generateKeyPackage, generateKeyPackageWithKey } from "../../src/keyPackage.js"
import { Credential } from "../../src/credential.js"
import {
  CiphersuiteId,
  CiphersuiteImpl,
  CiphersuiteName,
  ciphersuites,
  getCiphersuiteFromName,
} from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { CryptoVerificationError, ValidationError } from "../../src/mlsError.js"
import { ratchetTreeEncoder, RatchetTree, addLeafNode } from "../../src/ratchetTree.js"
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
import { protocolVersions, ProtocolVersionValue } from "../../src/protocolVersion.js"
import { signLeafNodeCommit, signLeafNodeKeyPackage } from "../../src/leafNode.js"
import { nodeToLeafIndex, toNodeIndex } from "../../src/treemath.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { leafNodeSources } from "../../src/leafNodeSource.js"
import { nodeTypes } from "../../src/nodeType.js"
import { encode } from "../../src/codec/tlsEncoder.js"

describe("Ratchet Tree Validation", () => {
  const suites = Object.keys(ciphersuites)

  test.concurrent.each(suites)("structural integrity %s", async (cs) => {
    await testStructuralIntegrity(cs as CiphersuiteName)
  })

  test.concurrent.each(suites)("invalid parent hash %s", async (cs) => {
    await testInvalidParentHash(cs as CiphersuiteName)
  })

  test.concurrent.each(suites)("invalid tree hash %s", async (cs) => {
    await testInvalidTreeHash(cs as CiphersuiteName)
  })

  test.concurrent.each(suites)("hpke public keys not unique %s", async (cs) => {
    await testHpkePublicKeysNotUnique(cs as CiphersuiteName)
  })

  test.concurrent.each(suites)("signature key not unique %s", async (cs) => {
    await testSignatureKeyNotUnique(cs as CiphersuiteName)
  })

  test.concurrent.each(suites)("invalid leaf node signature (commit) %s", async (cs) => {
    await testInvalidLeafNodeSignature(cs as CiphersuiteName)
  })

  test.concurrent.each(suites)("invalid leaf node signature (key package) %s", async (cs) => {
    await testInvalidLeafNodeSignatureKeyPackage(cs as CiphersuiteName)
  })

  test.concurrent.each(suites)("invalid keypackage signature %s", async (cs) => {
    await testInvalidKeyPackageSignature(cs as CiphersuiteName)
  })

  test.concurrent.each(suites)("invalid cipher suite %s", async (cs) => {
    await testInvalidCipherSuite(cs as CiphersuiteName)
  })

  test.concurrent.each(suites)("invalid mls version %s", async (cs) => {
    await testInvalidMlsVersion(cs as CiphersuiteName)
  })

  test.concurrent.each(suites)("invalid credential %s", async (cs) => {
    await testInvalidCredential(cs as CiphersuiteName)
  })
})

async function testStructuralIntegrity(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))
  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }

  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const validLeafNode = alice.publicPackage.leafNode
  // Make the first node a parent node, which is invalid for a leaf position
  const invalidTree: RatchetTree = [
    {
      nodeType: nodeTypes.parent,
      parent: {
        unmergedLeaves: [],
        parentHash: new Uint8Array(),
        hpkePublicKey: new Uint8Array(),
      },
    },
    { nodeType: nodeTypes.leaf, leaf: validLeafNode },
    { nodeType: nodeTypes.leaf, leaf: validLeafNode },
  ]

  const groupContext: GroupContext = {
    version: protocolVersions.mls10,
    cipherSuite: ciphersuites[cipherSuite],
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

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
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

  if (tree[0]!.nodeType === nodeTypes.parent || tree[0]!.leaf.leafNodeSource !== leafNodeSources.commit)
    throw new Error("expected leaf")

  // flip a byte in the parent hash to invalidate it
  tree[0]!.leaf.parentHash[0] = (tree[0]!.leaf.parentHash[0]! + 1) & 0xff

  await resignLeafNode(tree, 0, groupId, alice.privatePackage.signaturePrivateKey, impl)

  const treeExtension = groupInfo.extensions.find((ex) => ex.extensionType === defaultExtensionTypes.ratchet_tree)

  treeExtension!.extensionData = encode(ratchetTreeEncoder, tree)

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new CryptoVerificationError("Unable to verify parent hash"))
}

async function resignLeafNode(
  tree: RatchetTree,
  nodeIndex: number,
  groupId: Uint8Array,
  privateKey: Uint8Array,
  impl: CiphersuiteImpl,
) {
  if (tree[nodeIndex]!.nodeType === nodeTypes.parent) throw new Error("expected leaf")
  if (tree[nodeIndex]?.leaf.leafNodeSource === leafNodeSources.commit) {
    const newLeaf = {
      ...tree[nodeIndex].leaf,

      leafNodeSource: tree[nodeIndex].leaf.leafNodeSource,
      groupId,
      leafIndex: nodeToLeafIndex(toNodeIndex(nodeIndex)),
    }
    const signed = await signLeafNodeCommit(newLeaf, privateKey, impl.signature)
    tree[nodeIndex].leaf.signature = signed.signature
  } else if (tree[nodeIndex]?.leaf.leafNodeSource === leafNodeSources.key_package) {
    const signed = await signLeafNodeKeyPackage(
      { ...tree[nodeIndex]?.leaf, leafNodeSource: leafNodeSources.key_package },
      privateKey,
      impl.signature,
    )
    tree[nodeIndex].leaf.signature = signed.signature
  } else {
    throw new Error("Couldn't sign")
  }
}

async function testHpkePublicKeysNotUnique(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
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

  if (tree[0]!.nodeType === nodeTypes.parent || tree[2]!.nodeType === nodeTypes.parent) throw new Error("expected leaf")

  tree[0]!.leaf.hpkePublicKey = tree[2]!.leaf.hpkePublicKey

  await resignLeafNode(tree, 0, groupId, alice.privatePackage.signaturePrivateKey, impl)

  const treeExtension = groupInfo.extensions.find((ex) => ex.extensionType === defaultExtensionTypes.ratchet_tree)

  treeExtension!.extensionData = encode(ratchetTreeEncoder, tree)

  groupInfo.groupContext.treeHash = await treeHashRoot(tree, impl.hash)

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new ValidationError("hpke keys not unique"))
}

async function testInvalidLeafNodeSignature(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
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

  if (tree[0] === undefined || tree[0].nodeType === nodeTypes.parent) throw new Error("expected leaf")

  // flip a byte in the signature to invalidate it
  tree[0].leaf.signature[0] = (tree[0].leaf.signature[0]! + 1) & 0xff

  const treeExtension = groupInfo.extensions.find((ex) => ex.extensionType === defaultExtensionTypes.ratchet_tree)

  treeExtension!.extensionData = encode(ratchetTreeEncoder, tree)

  groupInfo.groupContext.treeHash = await treeHashRoot(tree, impl.hash)

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new CryptoVerificationError("Could not verify leaf node signature"))
}

async function testInvalidLeafNodeSignatureKeyPackage(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)

  // tamper with the key_package leaf node signature
  const tree = ratchetTreeFromExtension(groupInfo)!

  if (
    tree[0] === undefined ||
    tree[0].nodeType === nodeTypes.parent ||
    tree[0].leaf.leafNodeSource !== leafNodeSources.key_package
  )
    throw new Error("expected key_package leaf source")

  // flip a byte in the signature to invalidate it
  tree[0].leaf.signature[0] = (tree[0].leaf.signature[0]! + 1) & 0xff

  const treeExtension = groupInfo.extensions.find((ex) => ex.extensionType === defaultExtensionTypes.ratchet_tree)

  treeExtension!.extensionData = encode(ratchetTreeEncoder, tree)

  groupInfo.groupContext.treeHash = await treeHashRoot(tree, impl.hash)

  await expect(joinGroupExternal(groupInfo, bob.publicPackage, bob.privatePackage, false, impl)).rejects.toThrow(
    new CryptoVerificationError("Could not verify leaf node signature"),
  )
}

async function testInvalidKeyPackageSignature(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  // create an add proposal with a tampered keypackage signature
  bob.publicPackage.signature[0] = (bob.publicPackage.signature[0]! + 1) & 0xff

  const addBobProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
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

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  // tamper with the KeyPackage cipherSuite id to mismatch the group's cipher suite
  bob.publicPackage.cipherSuite = 0xffff as CiphersuiteId

  const addBobProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
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

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  // tamper with the KeyPackage version id to mismatch the group's version
  bob.publicPackage.version = 0xffff as ProtocolVersionValue

  const addBobProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
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

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
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

async function testSignatureKeyNotUnique(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const sigKeys = await impl.signature.keygen()

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackageWithKey(
    aliceCredential,
    defaultCapabilities(),
    defaultLifetime,
    [],
    sigKeys,
    impl,
  )

  const groupId = new TextEncoder().encode("group1")

  const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackageWithKey(bobCredential, defaultCapabilities(), defaultLifetime, [], sigKeys, impl)

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)
  const tree = ratchetTreeFromExtension(groupInfo)!

  // manually add bob with same signature key
  const [newTree] = addLeafNode(tree, bob.publicPackage.leafNode)

  const treeExtension = groupInfo.extensions.find((ex) => ex.extensionType === defaultExtensionTypes.ratchet_tree)
  treeExtension!.extensionData = encode(ratchetTreeEncoder, newTree)

  groupInfo.groupContext.treeHash = await treeHashRoot(newTree, impl.hash)

  await expect(
    joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl),
  ).rejects.toThrow(new ValidationError("signature keys not unique"))
}

async function testInvalidTreeHash(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
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
