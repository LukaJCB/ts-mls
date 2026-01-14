import { leafNodeEncoder, decodeLeafNode, LeafNode } from "../../src/leafNode.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { createRoundtripTest } from "./roundtrip.js"
import { leafNodeSources } from "../../src/leafNodeSource.js"

const minimalLeafNode: LeafNode = {
  hpkePublicKey: new Uint8Array([]),
  signaturePublicKey: new Uint8Array([]),
  credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([]) },
  capabilities: {
    versions: [],
    ciphersuites: [],
    extensions: [],
    proposals: [],
    credentials: [],
  },
  leafNodeSource: leafNodeSources.update,
  extensions: [],
  signature: new Uint8Array([]),
}

const nontrivialLeafNode: LeafNode = {
  hpkePublicKey: new Uint8Array([1, 2, 3]),
  signaturePublicKey: new Uint8Array([4, 5, 6]),
  credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([7, 8]) },
  capabilities: {
    versions: [protocolVersions.mls10],
    ciphersuites: [ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519],
    extensions: [7],
    proposals: [71],
    credentials: [defaultCredentialTypes.basic],
  },
  leafNodeSource: leafNodeSources.commit,
  parentHash: new Uint8Array([9, 10]),
  extensions: [{ extensionType: defaultExtensionTypes.application_id, extensionData: new Uint8Array([11, 12]) }],
  signature: new Uint8Array([13, 14]),
}

describe("LeafNode roundtrip", () => {
  const roundtrip = createRoundtripTest(leafNodeEncoder, decodeLeafNode)

  test("roundtrips minimal", () => {
    roundtrip(minimalLeafNode)
  })

  test("roundtrips nontrivial", () => {
    roundtrip(nontrivialLeafNode)
  })
})
