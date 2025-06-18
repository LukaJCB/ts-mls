import { getCiphersuiteFromId, getCiphersuiteImpl } from "../src/crypto/ciphersuite"
import { GroupContext } from "../src/groupContext"
import { GroupInfoTBS, signGroupInfo, verifyGroupInfoSignature } from "../src/groupInfo"
import { ed25519 } from "@noble/curves/ed25519"

describe("GroupInfo signing and verification", () => {
  const privateKey = ed25519.utils.randomPrivateKey()
  const publicKey = ed25519.getPublicKey(privateKey)

  const groupContext: GroupContext = {
    version: "mls10",
    cipherSuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    groupId: new Uint8Array([0x01, 0x02]),
    epoch: BigInt(42),
    treeHash: new Uint8Array([0xaa]),
    confirmedTranscriptHash: new Uint8Array([0xbb]),
    extensions: [{ extensionType: "application_id", extensionData: new Uint8Array([0x11]) }],
  }

  const baseTBS: GroupInfoTBS = {
    groupContext,
    extensions: [{ extensionType: "ratchet_tree", extensionData: new Uint8Array([0x22]) }],
    confirmationTag: new Uint8Array([0xcc]),
    signer: 7,
  }

  test("signs and verifies successfully", async () => {
    const cs = await getCiphersuiteImpl(getCiphersuiteFromId(1))
    const gi = signGroupInfo(baseTBS, privateKey, cs.signature)
    expect(verifyGroupInfoSignature(gi, publicKey, cs.signature)).toBe(true)
  })

  test("fails verification if confirmationTag is changed", async () => {
    const cs = await getCiphersuiteImpl(getCiphersuiteFromId(1))
    const gi = signGroupInfo(baseTBS, privateKey, cs.signature)
    const modified = { ...gi, confirmationTag: new Uint8Array([0xdd]) }
    expect(verifyGroupInfoSignature(modified, publicKey, cs.signature)).toBe(false)
  })

  test("fails verification if signature is tampered", async () => {
    const cs = await getCiphersuiteImpl(getCiphersuiteFromId(1))
    const gi = signGroupInfo(baseTBS, privateKey, cs.signature)
    const tampered = { ...gi, signature: gi.signature.fill(0, 2, 4) }
    expect(verifyGroupInfoSignature(tampered, publicKey, cs.signature)).toBe(false)
  })
})
