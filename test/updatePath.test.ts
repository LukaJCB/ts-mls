import { createUpdatePath } from "../src/updatePath.js"
import { RatchetTree } from "../src/ratchetTree.js"
import { GroupContext } from "../src/groupContext.js"
import { getCiphersuiteImpl } from "../src/crypto/getCiphersuiteImpl.js"
import { ciphersuites, getCiphersuiteFromName } from "../src/crypto/ciphersuite.js"
import { toLeafIndex } from "../src/treemath.js"
import { LeafNodeCommit } from "../src/leafNode.js"
import { protocolVersions } from "../src/protocolVersion.js"
import { defaultCredentialTypes } from "../src/defaultCredentialType.js"

describe("createUpdatePath", () => {
  test("should not modify the original tree", async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"))

    const leaf1: LeafNodeCommit = {
      leafNodeSource: "commit",
      hpkePublicKey: impl.rng.randomBytes(32),
      signaturePublicKey: impl.rng.randomBytes(32),
      credential: {
        credentialType: defaultCredentialTypes.basic,
        identity: new TextEncoder().encode("user1"),
      },
      capabilities: {
        versions: [protocolVersions.mls10],
        ciphersuites: [ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
        extensions: [],
        proposals: [],
        credentials: [],
      },
      extensions: [],
      signature: new Uint8Array(64),
      parentHash: new Uint8Array(32),
    }

    const leaf2: LeafNodeCommit = {
      ...leaf1,
      hpkePublicKey: impl.rng.randomBytes(32),
      signaturePublicKey: impl.rng.randomBytes(32),
      credential: {
        credentialType: defaultCredentialTypes.basic,
        identity: new TextEncoder().encode("user2"),
      },
    }

    const originalTree: RatchetTree = [
      { nodeType: "leaf", leaf: leaf1 },
      {
        nodeType: "parent",
        parent: {
          hpkePublicKey: impl.rng.randomBytes(32),
          parentHash: new Uint8Array(32),
          unmergedLeaves: [],
        },
      },
      { nodeType: "leaf", leaf: leaf2 },
    ]

    if (originalTree[0]?.nodeType !== "leaf" || originalTree[2]?.nodeType !== "leaf") throw new Error("Expected leaf")

    if (originalTree[1]?.nodeType !== "parent") throw new Error("Expected parent")

    const originalLeaf0HpkeKey = originalTree[0].leaf.hpkePublicKey.slice()

    const originalLeaf0SigKey = originalTree[0].leaf.signaturePublicKey.slice()

    const originalParent1HpkeKey = originalTree[1].parent.hpkePublicKey.slice()

    const originalLeaf2HpkeKey = originalTree[2].leaf.hpkePublicKey.slice()

    const groupContext: GroupContext = {
      version: protocolVersions.mls10,
      cipherSuite: ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
      groupId: new Uint8Array(16),
      epoch: 1n,
      treeHash: new Uint8Array(32),
      confirmedTranscriptHash: new Uint8Array(32),
      extensions: [],
    }

    const signaturePrivateKey = impl.rng.randomBytes(32)
    const senderLeafIndex = toLeafIndex(0)

    await createUpdatePath(originalTree, senderLeafIndex, groupContext, signaturePrivateKey, impl)

    expect(originalTree[0].leaf.hpkePublicKey).toStrictEqual(originalLeaf0HpkeKey)
    expect(originalTree[0].leaf.signaturePublicKey).toStrictEqual(originalLeaf0SigKey)
    expect(originalTree[1].parent.hpkePublicKey).toStrictEqual(originalParent1HpkeKey)
    expect(originalTree[2].leaf.hpkePublicKey).toStrictEqual(originalLeaf2HpkeKey)
  })

  test("should not modify the original tree with multiple nodes", async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"))

    const createLeaf = (identity: string): LeafNodeCommit => ({
      leafNodeSource: "commit",
      hpkePublicKey: impl.rng.randomBytes(32),
      signaturePublicKey: impl.rng.randomBytes(32),
      credential: {
        credentialType: defaultCredentialTypes.basic,
        identity: new TextEncoder().encode(identity),
      },
      capabilities: {
        versions: [protocolVersions.mls10],
        ciphersuites: [ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
        extensions: [],
        proposals: [],
        credentials: [],
      },
      extensions: [],
      signature: new Uint8Array(64),
      parentHash: new Uint8Array(32),
    })

    const createParent = () => ({
      nodeType: "parent" as const,
      parent: {
        hpkePublicKey: impl.rng.randomBytes(32),
        parentHash: new Uint8Array(32),
        unmergedLeaves: [],
      },
    })

    const originalTree: RatchetTree = [
      { nodeType: "leaf", leaf: createLeaf("user1") },
      createParent(),
      { nodeType: "leaf", leaf: createLeaf("user2") },
      createParent(),
      { nodeType: "leaf", leaf: createLeaf("user3") },
      createParent(),
      { nodeType: "leaf", leaf: createLeaf("user4") },
    ]

    if (
      originalTree[0]?.nodeType !== "leaf" ||
      originalTree[2]?.nodeType !== "leaf" ||
      originalTree[4]?.nodeType !== "leaf" ||
      originalTree[6]?.nodeType !== "leaf"
    )
      throw new Error("Expected leaf")

    if (
      originalTree[1]?.nodeType !== "parent" ||
      originalTree[3]?.nodeType !== "parent" ||
      originalTree[5]?.nodeType !== "parent"
    )
      throw new Error("Expected parent")

    const originalLeaf0HpkeKey = originalTree[0].leaf.hpkePublicKey.slice()
    const originalLeaf2HpkeKey = originalTree[2].leaf.hpkePublicKey.slice()
    const originalLeaf4HpkeKey = originalTree[4].leaf.hpkePublicKey.slice()

    const originalLeaf6HpkeKey = originalTree[6].leaf.hpkePublicKey.slice()

    const originalParent1HpkeKey = originalTree[1].parent.hpkePublicKey.slice()

    const originalParent3HpkeKey = originalTree[3].parent.hpkePublicKey.slice()

    const originalParent5HpkeKey = originalTree[5].parent.hpkePublicKey.slice()

    const groupContext: GroupContext = {
      version: protocolVersions.mls10,
      cipherSuite: ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
      groupId: new Uint8Array(16),
      epoch: 1n,
      treeHash: new Uint8Array(32),
      confirmedTranscriptHash: new Uint8Array(32),
      extensions: [],
    }

    const signaturePrivateKey = impl.rng.randomBytes(32)
    const senderLeafIndex = toLeafIndex(1)

    await createUpdatePath(originalTree, senderLeafIndex, groupContext, signaturePrivateKey, impl)

    expect(originalTree[0].leaf.hpkePublicKey).toStrictEqual(originalLeaf0HpkeKey)
    expect(originalTree[2].leaf.hpkePublicKey).toStrictEqual(originalLeaf2HpkeKey)
    expect(originalTree[4].leaf.hpkePublicKey).toStrictEqual(originalLeaf4HpkeKey)
    expect(originalTree[6].leaf.hpkePublicKey).toStrictEqual(originalLeaf6HpkeKey)
    expect(originalTree[1].parent.hpkePublicKey).toStrictEqual(originalParent1HpkeKey)
    expect(originalTree[3].parent.hpkePublicKey).toStrictEqual(originalParent3HpkeKey)
    expect(originalTree[5].parent.hpkePublicKey).toStrictEqual(originalParent5HpkeKey)
  })
})
