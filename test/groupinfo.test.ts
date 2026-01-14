import { ciphersuites, getCiphersuiteFromId } from "../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../src/crypto/getCiphersuiteImpl.js"
import { GroupContext } from "../src/groupContext.js"
import { GroupInfoTBS, signGroupInfo, verifyGroupInfoSignature } from "../src/groupInfo.js"
import { ed25519 } from "@noble/curves/ed25519.js"
import { protocolVersions } from "../src/protocolVersion.js"
import { defaultExtensionTypes } from "../src/defaultExtensionType.js"
import { makeCustomExtension } from "../src/extension.js"

describe("GroupInfo signing and verification", () => {
  const privateKey = ed25519.utils.randomSecretKey()
  const publicKey = ed25519.getPublicKey(privateKey)

  const groupContext: GroupContext = {
    version: protocolVersions.mls10,
    cipherSuite: ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    groupId: new Uint8Array([0x01, 0x02]),
    epoch: BigInt(42),
    treeHash: new Uint8Array([0xaa]),
    confirmedTranscriptHash: new Uint8Array([0xbb]),
    extensions: [makeCustomExtension(91, new Uint8Array([0x11]))],
  }

  const baseTBS: GroupInfoTBS = {
    groupContext,
    extensions: [{ extensionType: defaultExtensionTypes.external_pub, extensionData: new Uint8Array([0x22]) }],
    confirmationTag: new Uint8Array([0xcc]),
    signer: 7,
  }

  test("signs and verifies successfully", async () => {
    const cs = await getCiphersuiteImpl(getCiphersuiteFromId(1))
    const gi = await signGroupInfo(baseTBS, privateKey, cs.signature)
    expect(await verifyGroupInfoSignature(gi, publicKey, cs.signature)).toBe(true)
  })

  test("fails verification if confirmationTag is changed", async () => {
    const cs = await getCiphersuiteImpl(getCiphersuiteFromId(1))
    const gi = await signGroupInfo(baseTBS, privateKey, cs.signature)
    const modified = { ...gi, confirmationTag: new Uint8Array([0xdd]) }
    expect(await verifyGroupInfoSignature(modified, publicKey, cs.signature)).toBe(false)
  })

  test("fails verification if signature is tampered", async () => {
    const cs = await getCiphersuiteImpl(getCiphersuiteFromId(1))
    const gi = await signGroupInfo(baseTBS, privateKey, cs.signature)
    const tampered = { ...gi, signature: gi.signature.fill(0, 2, 4) }
    expect(await verifyGroupInfoSignature(tampered, publicKey, cs.signature)).toBe(false)
  })
})
