import {
  groupInfoTBSEncoder,
  groupInfoTBSDecoder,
  GroupInfoTBS,
  groupInfoEncoder,
  groupInfoDecoder,
  GroupInfo,
} from "../../src/groupInfo.js"
import { createRoundtripTest } from "./roundtrip.js"
import { GroupContext } from "../../src/groupContext.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"

const dummyGroupContext: GroupContext = {
  version: protocolVersions.mls10,
  cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
  groupId: new Uint8Array([1, 2, 3]),
  epoch: 0n,
  treeHash: new Uint8Array([4, 5]),
  confirmedTranscriptHash: new Uint8Array([6]),
  extensions: [],
}
const dummyExtension = {
  extensionType: defaultExtensionTypes.ratchet_tree,
  extensionData: new Uint8Array([8, 9]),
} as const

const minimalTBS: GroupInfoTBS = {
  groupContext: dummyGroupContext,
  extensions: [],
  confirmationTag: new Uint8Array([]),
  signer: 0,
}

const nontrivialTBS: GroupInfoTBS = {
  groupContext: dummyGroupContext,
  extensions: [dummyExtension],
  confirmationTag: new Uint8Array([1, 2, 3]),
  signer: 42,
}

describe("GroupInfoTBS roundtrip", () => {
  const roundtrip = createRoundtripTest(groupInfoTBSEncoder, groupInfoTBSDecoder)
  test("roundtrips minimal", () => {
    roundtrip(minimalTBS)
  })
  test("roundtrips nontrivial", () => {
    roundtrip(nontrivialTBS)
  })
})

describe("GroupInfo roundtrip", () => {
  const roundtrip = createRoundtripTest(groupInfoEncoder, groupInfoDecoder)
  test("roundtrips minimal", () => {
    const g: GroupInfo = { ...minimalTBS, signature: new Uint8Array([]) }
    roundtrip(g)
  })
  test("roundtrips nontrivial", () => {
    const g: GroupInfo = { ...nontrivialTBS, signature: new Uint8Array([9, 8, 7]) }
    roundtrip(g)
  })
})
