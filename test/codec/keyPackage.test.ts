import { encodeKeyPackage, decodeKeyPackage, KeyPackage } from "../../src/keyPackage.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { createRoundtripTest } from "./roundtrip.js"

const minimalKeyPackage: KeyPackage = {
  version: protocolVersions.mls10,
  cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
  initKey: new Uint8Array([]),
  leafNode: {
    hpkePublicKey: new Uint8Array([]),
    signaturePublicKey: new Uint8Array([]),
    credential: { credentialType: "basic", identity: new Uint8Array([]) },
    capabilities: {
      versions: [],
      ciphersuites: [],
      extensions: [],
      proposals: [],
      credentials: [],
    },
    leafNodeSource: "key_package",
    lifetime: { notBefore: 0n, notAfter: 0n },
    extensions: [],
    signature: new Uint8Array([]),
  },
  extensions: [],
  signature: new Uint8Array([]),
}

const nontrivialKeyPackage: KeyPackage = {
  version: protocolVersions.mls10,
  cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
  initKey: new Uint8Array([1, 2, 3]),
  leafNode: {
    hpkePublicKey: new Uint8Array([4, 5]),
    signaturePublicKey: new Uint8Array([6, 7]),
    credential: { credentialType: "basic", identity: new Uint8Array([8, 9]) },
    capabilities: {
      versions: [protocolVersions.mls10],
      ciphersuites: [ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519],
      extensions: [8],
      proposals: [9],
      credentials: ["basic"],
    },
    leafNodeSource: "key_package",
    lifetime: { notBefore: 1n, notAfter: 2n },
    extensions: [{ extensionType: "ratchet_tree", extensionData: new Uint8Array([10, 11]) }],
    signature: new Uint8Array([12, 13]),
  },
  extensions: [{ extensionType: "ratchet_tree", extensionData: new Uint8Array([14, 15]) }],
  signature: new Uint8Array([16, 17]),
}

describe("KeyPackage roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeKeyPackage, decodeKeyPackage)

  test("roundtrips minimal", () => {
    roundtrip(minimalKeyPackage)
  })

  test("roundtrips nontrivial", () => {
    roundtrip(nontrivialKeyPackage)
  })
})
