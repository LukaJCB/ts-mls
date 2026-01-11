import { encodeGroupContext, decodeGroupContext, GroupContext } from "../../src/groupContext.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { createRoundtripTest } from "./roundtrip.js"

const minimalGroupContext: GroupContext = {
  version: protocolVersions.mls10,
  cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
  groupId: new Uint8Array([]),
  epoch: 0n,
  treeHash: new Uint8Array([]),
  confirmedTranscriptHash: new Uint8Array([]),
  extensions: [],
}

const nontrivialGroupContext: GroupContext = {
  version: protocolVersions.mls10,
  cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
  groupId: new Uint8Array([1, 2, 3]),
  epoch: 42n,
  treeHash: new Uint8Array([4, 5]),
  confirmedTranscriptHash: new Uint8Array([6, 7]),
  extensions: [{ extensionType: "ratchet_tree", extensionData: new Uint8Array([8, 9]) }],
}

describe("GroupContext roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeGroupContext, decodeGroupContext)

  test("roundtrips minimal", () => {
    roundtrip(minimalGroupContext)
  })

  test("roundtrips nontrivial", () => {
    roundtrip(nontrivialGroupContext)
  })
})
