import { encodeKeyPackageTBS, decodeKeyPackageTBS } from "../../src/keyPackage"
import { createRoundtripTest } from "./roundtrip.js"

describe("KeyPackageTBS roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeKeyPackageTBS, decodeKeyPackageTBS)

  test("roundtrips minimal", () => {
    const tbs = {
      version: "mls10" as const,
      cipherSuite: "MLS_256_XWING_AES256GCM_SHA512_Ed25519" as const,
      initKey: new Uint8Array([1, 2, 3]),
      leafNode: {
        hpkePublicKey: new Uint8Array([4, 5, 6]),
        signaturePublicKey: new Uint8Array([7, 8, 9]),
        credential: { credentialType: "basic" as const, identity: new Uint8Array([10, 11, 12]) },
        capabilities: {
          versions: [],
          ciphersuites: [],
          extensions: [],
          proposals: [],
          credentials: [],
        },
        leafNodeSource: "key_package" as const,
        lifetime: { notBefore: 0n, notAfter: 0n },
        extensions: [],
        signature: new Uint8Array([13, 14, 15]),
      },
      extensions: [],
    }
    roundtrip(tbs)
  })

  test("roundtrips nontrivial", () => {
    const tbs = {
      version: "mls10" as const,
      cipherSuite: "MLS_256_XWING_AES256GCM_SHA512_Ed25519" as const,
      initKey: new Uint8Array([16, 17, 18, 19, 20]),
      leafNode: {
        hpkePublicKey: new Uint8Array([21, 22, 23, 24, 25]),
        signaturePublicKey: new Uint8Array([26, 27, 28, 29, 30]),
        credential: {
          credentialType: "x509" as const,
          certificates: [new Uint8Array([31, 32]), new Uint8Array([33, 34, 35])],
        },
        capabilities: {
          versions: ["mls10" as const],
          ciphersuites: ["MLS_256_XWING_AES256GCM_SHA512_Ed25519" as const],
          extensions: [7, 8, 9],
          proposals: [9, 10, 11],
          credentials: ["basic" as const, "x509" as const],
        },
        leafNodeSource: "key_package" as const,
        lifetime: { notBefore: 1000n, notAfter: 2000n },
        extensions: [{ extensionType: "application_id" as const, extensionData: new Uint8Array([36, 37, 38]) }],
        signature: new Uint8Array([39, 40, 41, 42, 43]),
      },
      extensions: [{ extensionType: "application_id" as const, extensionData: new Uint8Array([44, 45, 46]) }],
    }
    roundtrip(tbs)
  })
})
