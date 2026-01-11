import { decodeUpdatePath, encodeUpdatePath, UpdatePath } from "../../src/updatePath.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"

describe("UpdatePath", () => {
  test("minimal roundtrip", () => {
    const minimal: UpdatePath = {
      leafNode: {
        hpkePublicKey: new Uint8Array([1, 2, 3]),
        signaturePublicKey: new Uint8Array([4, 5, 6]),
        credential: {
          credentialType: "basic",
          identity: new Uint8Array([7, 8, 9]),
        },
        capabilities: {
          versions: ["mls10"],
          ciphersuites: [ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
          extensions: [],
          proposals: [],
          credentials: [],
        },
        leafNodeSource: "commit",
        parentHash: new Uint8Array([10, 11, 12]),
        extensions: [],
        signature: new Uint8Array([13, 14, 15]),
      },
      nodes: [],
    }

    const encoded = encodeUpdatePath(minimal)
    const decoded = decodeUpdatePath(encoded, 0)![0]
    expect(decoded).toEqual(minimal)
  })

  test("non-trivial roundtrip", () => {
    const nonTrivial: UpdatePath = {
      leafNode: {
        hpkePublicKey: new Uint8Array([16, 17, 18, 19, 20]),
        signaturePublicKey: new Uint8Array([21, 22, 23, 24, 25]),
        credential: {
          credentialType: "basic",
          identity: new Uint8Array([26, 27, 28, 29, 30]),
        },
        capabilities: {
          versions: ["mls10"],
          ciphersuites: [ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
          extensions: [],
          proposals: [],
          credentials: [],
        },
        leafNodeSource: "commit",
        parentHash: new Uint8Array([31, 32, 33, 34, 35]),
        extensions: [],
        signature: new Uint8Array([36, 37, 38, 39, 40]),
      },
      nodes: [
        {
          hpkePublicKey: new Uint8Array([41, 42, 43]),
          encryptedPathSecret: [
            {
              ciphertext: new Uint8Array([44, 45, 46]),
              kemOutput: new Uint8Array([47, 48, 49]),
            },
            {
              ciphertext: new Uint8Array([50, 51, 52]),
              kemOutput: new Uint8Array([53, 54, 55]),
            },
          ],
        },
        {
          hpkePublicKey: new Uint8Array([56, 57, 58]),
          encryptedPathSecret: [
            {
              ciphertext: new Uint8Array([59, 60, 61]),
              kemOutput: new Uint8Array([62, 63, 64]),
            },
          ],
        },
      ],
    }

    const encoded = encodeUpdatePath(nonTrivial)
    const decoded = decodeUpdatePath(encoded, 0)![0]
    expect(decoded).toEqual(nonTrivial)
  })
})
