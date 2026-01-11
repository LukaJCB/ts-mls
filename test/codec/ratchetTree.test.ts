import { encodeRatchetTree, decodeRatchetTree, RatchetTree } from "../../src/ratchetTree.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"

describe("RatchetTree roundtrip", () => {
  test("roundtrips single leaf", () => {
    const data: RatchetTree = [
      {
        nodeType: "leaf",
        leaf: {
          hpkePublicKey: new Uint8Array([1]),
          signaturePublicKey: new Uint8Array([2]),
          credential: { credentialType: "basic", identity: new Uint8Array([3]) },
          capabilities: {
            versions: ["mls10"],
            ciphersuites: [ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519],
            extensions: [],
            proposals: [],
            credentials: [],
          },
          leafNodeSource: "key_package",
          lifetime: { notBefore: 0n, notAfter: 0n },
          extensions: [],
          signature: new Uint8Array([4]),
        },
      },
    ]
    const encoded = encodeRatchetTree(data)
    const decoded = decodeRatchetTree(encoded, 0)?.[0] as RatchetTree
    expect(decoded).toStrictEqual(data)
  })

  test("roundtrips tree", () => {
    const data: RatchetTree = [
      {
        nodeType: "leaf",
        leaf: {
          hpkePublicKey: new Uint8Array([1]),
          signaturePublicKey: new Uint8Array([2]),
          credential: { credentialType: "basic", identity: new Uint8Array([3]) },
          capabilities: {
            versions: ["mls10"],
            ciphersuites: [ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519],
            extensions: [],
            proposals: [],
            credentials: [],
          },
          leafNodeSource: "key_package",
          lifetime: { notBefore: 0n, notAfter: 0n },
          extensions: [],
          signature: new Uint8Array([4]),
        },
      },
      {
        nodeType: "parent",
        parent: {
          hpkePublicKey: new Uint8Array([1, 2]),
          parentHash: new Uint8Array([3, 4]),
          unmergedLeaves: [0],
        },
      },
      {
        nodeType: "leaf",
        leaf: {
          hpkePublicKey: new Uint8Array([5]),
          signaturePublicKey: new Uint8Array([6]),
          credential: { credentialType: "basic", identity: new Uint8Array([7]) },
          capabilities: {
            versions: ["mls10"],
            ciphersuites: [ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519],
            extensions: [],
            proposals: [],
            credentials: [],
          },
          leafNodeSource: "key_package",
          lifetime: { notBefore: 0n, notAfter: 0n },
          extensions: [],
          signature: new Uint8Array([4]),
        },
      },
    ]
    const encoded = encodeRatchetTree(data)
    const decoded = decodeRatchetTree(encoded, 0)?.[0] as RatchetTree
    expect(decoded).toStrictEqual(data)
  })
})
