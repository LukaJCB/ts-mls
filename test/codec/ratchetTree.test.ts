import { ratchetTreeEncoder, decodeRatchetTree, RatchetTree } from "../../src/ratchetTree.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { leafNodeSources } from "../../src/leafNodeSource.js"
import { nodeTypes } from "../../src/nodeType.js"
import { encode } from "../../src/codec/tlsEncoder.js"

describe("RatchetTree roundtrip", () => {
  test("roundtrips single leaf", () => {
    const data: RatchetTree = [
      {
        nodeType: nodeTypes.leaf,
        leaf: {
          hpkePublicKey: new Uint8Array([1]),
          signaturePublicKey: new Uint8Array([2]),
          credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([3]) },
          capabilities: {
            versions: [protocolVersions.mls10],
            ciphersuites: [ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519],
            extensions: [],
            proposals: [],
            credentials: [],
          },
          leafNodeSource: leafNodeSources.key_package,
          lifetime: { notBefore: 0n, notAfter: 0n },
          extensions: [],
          signature: new Uint8Array([4]),
        },
      },
    ]
    const encoded = encode(ratchetTreeEncoder, data)
    const decoded = decodeRatchetTree(encoded, 0)?.[0] as RatchetTree
    expect(decoded).toStrictEqual(data)
  })

  test("roundtrips tree", () => {
    const data: RatchetTree = [
      {
        nodeType: nodeTypes.leaf,
        leaf: {
          hpkePublicKey: new Uint8Array([1]),
          signaturePublicKey: new Uint8Array([2]),
          credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([3]) },
          capabilities: {
            versions: [protocolVersions.mls10],
            ciphersuites: [ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519],
            extensions: [],
            proposals: [],
            credentials: [],
          },
          leafNodeSource: leafNodeSources.key_package,
          lifetime: { notBefore: 0n, notAfter: 0n },
          extensions: [],
          signature: new Uint8Array([4]),
        },
      },
      {
        nodeType: nodeTypes.parent,
        parent: {
          hpkePublicKey: new Uint8Array([1, 2]),
          parentHash: new Uint8Array([3, 4]),
          unmergedLeaves: [0],
        },
      },
      {
        nodeType: nodeTypes.leaf,
        leaf: {
          hpkePublicKey: new Uint8Array([5]),
          signaturePublicKey: new Uint8Array([6]),
          credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([7]) },
          capabilities: {
            versions: [protocolVersions.mls10],
            ciphersuites: [ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519],
            extensions: [],
            proposals: [],
            credentials: [],
          },
          leafNodeSource: leafNodeSources.key_package,
          lifetime: { notBefore: 0n, notAfter: 0n },
          extensions: [],
          signature: new Uint8Array([4]),
        },
      },
    ]
    const encoded = encode(ratchetTreeEncoder, data)
    const decoded = decodeRatchetTree(encoded, 0)?.[0] as RatchetTree
    expect(decoded).toStrictEqual(data)
  })
})
