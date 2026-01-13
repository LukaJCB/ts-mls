import { keyPackageTBSEncoder, keyPackageTBSDecoder } from "../../src/keyPackage.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { createRoundtripTest } from "./roundtrip.js"
import { leafNodeSources } from "../../src/leafNodeSource.js"

describe("KeyPackageTBS roundtrip", () => {
  const roundtrip = createRoundtripTest(keyPackageTBSEncoder, keyPackageTBSDecoder)

  test("roundtrips minimal", () => {
    const tbs = {
      version: protocolVersions.mls10,
      cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
      initKey: new Uint8Array([1, 2, 3]),
      leafNode: {
        hpkePublicKey: new Uint8Array([4, 5, 6]),
        signaturePublicKey: new Uint8Array([7, 8, 9]),
        credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([10, 11, 12]) },
        capabilities: {
          versions: [],
          ciphersuites: [],
          extensions: [],
          proposals: [],
          credentials: [],
        },
        leafNodeSource: leafNodeSources.key_package,
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
      version: protocolVersions.mls10,
      cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
      initKey: new Uint8Array([16, 17, 18, 19, 20]),
      leafNode: {
        hpkePublicKey: new Uint8Array([21, 22, 23, 24, 25]),
        signaturePublicKey: new Uint8Array([26, 27, 28, 29, 30]),
        credential: {
          credentialType: defaultCredentialTypes.x509,
          certificates: [new Uint8Array([31, 32]), new Uint8Array([33, 34, 35])],
        },
        capabilities: {
          versions: [protocolVersions.mls10],
          ciphersuites: [ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519],
          extensions: [7, 8, 9],
          proposals: [9, 10, 11],
          credentials: [defaultCredentialTypes.basic, defaultCredentialTypes.x509],
        },
        leafNodeSource: leafNodeSources.key_package,
        lifetime: { notBefore: 1000n, notAfter: 2000n },
        extensions: [
          { extensionType: defaultExtensionTypes.application_id, extensionData: new Uint8Array([36, 37, 38]) },
        ],
        signature: new Uint8Array([39, 40, 41, 42, 43]),
      },
      extensions: [
        { extensionType: defaultExtensionTypes.application_id, extensionData: new Uint8Array([44, 45, 46]) },
      ],
    }
    roundtrip(tbs)
  })
})
