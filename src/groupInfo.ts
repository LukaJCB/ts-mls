import { decodeUint32, encodeUint32 } from "./codec/number"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { deriveSecret, Kdf } from "./crypto/kdf"
import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature"
import { decodeExtension, encodeExtension, Extension } from "./extension"
import { decodeGroupContext, encodeGroupContext, extractEpochSecret, GroupContext } from "./groupContext"
import { CodecError } from "./mlsError"
import { decodeRatchetTree, RatchetTree } from "./ratchetTree"

export type GroupInfoTBS = Readonly<{
  groupContext: GroupContext
  extensions: Extension[]
  confirmationTag: Uint8Array
  signer: number
}>

export const encodeGroupInfoTBS: Encoder<GroupInfoTBS> = contramapEncoders(
  [encodeGroupContext, encodeVarLenType(encodeExtension), encodeVarLenData, encodeUint32],
  (g) => [g.groupContext, g.extensions, g.confirmationTag, g.signer] as const,
)

export const decodeGroupInfoTBS: Decoder<GroupInfoTBS> = mapDecoders(
  [decodeGroupContext, decodeVarLenType(decodeExtension), decodeVarLenData, decodeUint32],
  (groupContext, extensions, confirmationTag, signer) => ({
    groupContext,
    extensions,
    confirmationTag,
    signer,
  }),
)

export type GroupInfo = GroupInfoTBS &
  Readonly<{
    signature: Uint8Array
  }>

export const encodeGroupInfo: Encoder<GroupInfo> = contramapEncoders(
  [encodeGroupInfoTBS, encodeVarLenData],
  (g) => [g, g.signature] as const,
)

export const decodeGroupInfo: Decoder<GroupInfo> = mapDecoders(
  [decodeGroupInfoTBS, decodeVarLenData],
  (tbs, signature) => ({
    ...tbs,
    signature,
  }),
)

export function ratchetTreeFromExtension(info: GroupInfo): RatchetTree | undefined {
  const treeExtension = info.extensions.find((ex) => ex.extensionType === "ratchet_tree")

  if (treeExtension !== undefined) {
    const tree = decodeRatchetTree(treeExtension.extensionData, 0)
    if (tree === undefined) throw new CodecError("Could not decode RatchetTree")
    return tree[0]
  }
}

export async function signGroupInfo(tbs: GroupInfoTBS, privateKey: Uint8Array, s: Signature): Promise<GroupInfo> {
  const signature = await signWithLabel(privateKey, "GroupInfoTBS", encodeGroupInfoTBS(tbs), s)
  return { ...tbs, signature }
}

export function verifyGroupInfoSignature(gi: GroupInfo, publicKey: Uint8Array, s: Signature): Promise<boolean> {
  return verifyWithLabel(publicKey, "GroupInfoTBS", encodeGroupInfoTBS(gi), gi.signature, s)
}

export async function verifyGroupInfoConfirmationTag(
  gi: GroupInfo,
  joinerSecret: Uint8Array,
  pskSecret: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<boolean> {
  const epochSecret = await extractEpochSecret(gi.groupContext, joinerSecret, cs.kdf, pskSecret)
  const key = await deriveSecret(epochSecret, "confirm", cs.kdf)
  return cs.hash.verifyMac(key, gi.confirmationTag, gi.groupContext.confirmedTranscriptHash)
}

export async function extractWelcomeSecret(joinerSecret: Uint8Array, pskSecret: Uint8Array, kdf: Kdf) {
  return deriveSecret(await kdf.extract(joinerSecret, pskSecret), "welcome", kdf)
}
