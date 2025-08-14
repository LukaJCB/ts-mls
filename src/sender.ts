import { decodeUint32, decodeUint64, decodeUint8, encodeUint32, encodeUint64, encodeUint8 } from "./codec/number"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { ContentTypeName, decodeContentType, encodeContentType } from "./contentType"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { expandWithLabel } from "./crypto/kdf"
import { enumNumberToKey } from "./util/enumHelpers"

const senderTypes = {
  member: 1,
  external: 2,
  new_member_proposal: 3,
  new_member_commit: 4,
} as const

export type SenderTypeName = keyof typeof senderTypes
export type SenderTypeValue = (typeof senderTypes)[SenderTypeName]

export const encodeSenderType: Encoder<SenderTypeName> = contramapEncoder(encodeUint8, (t) => senderTypes[t])

export const decodeSenderType: Decoder<SenderTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(senderTypes))

export interface SenderMember {
  senderType: "member"
  leafIndex: number
}

export type SenderNonMember = SenderExternal | SenderNewMemberProposal | SenderNewMemberCommit

export interface SenderExternal {
  senderType: "external"
  senderIndex: number
}
export interface SenderNewMemberProposal {
  senderType: "new_member_proposal"
}
export interface SenderNewMemberCommit {
  senderType: "new_member_commit"
}

export type Sender = SenderMember | SenderNonMember

export const encodeSender: Encoder<Sender> = (s) => {
  switch (s.senderType) {
    case "member":
      return contramapEncoders(
        [encodeSenderType, encodeUint32],
        (s: SenderMember) => [s.senderType, s.leafIndex] as const,
      )(s)
    case "external":
      return contramapEncoders(
        [encodeSenderType, encodeUint32],
        (s: SenderExternal) => [s.senderType, s.senderIndex] as const,
      )(s)
    case "new_member_proposal":
    case "new_member_commit":
      return encodeSenderType(s.senderType)
  }
}

export const decodeSender: Decoder<Sender> = flatMapDecoder(decodeSenderType, (senderType): Decoder<Sender> => {
  switch (senderType) {
    case "member":
      return mapDecoder(decodeUint32, (leafIndex) => ({
        senderType,
        leafIndex,
      }))
    case "external":
      return mapDecoder(decodeUint32, (senderIndex) => ({
        senderType,
        senderIndex,
      }))
    case "new_member_proposal":
      return mapDecoder(
        () => [undefined, 0],
        () => ({
          senderType,
        }),
      )
    case "new_member_commit":
      return mapDecoder(
        () => [undefined, 0],
        () => ({
          senderType,
        }),
      )
  }
})

export function getSenderLeafNodeIndex(sender: Sender): number | undefined {
  return sender.senderType === "member" ? sender.leafIndex : undefined
}

export interface SenderData {
  leafIndex: number
  generation: number
  reuseGuard: ReuseGuard
}

export type ReuseGuard = Uint8Array & { length: 4 }

export const encodeReuseGuard: Encoder<ReuseGuard> = (g) => g

export const decodeReuseGuard: Decoder<ReuseGuard> = (b, offset) => {
  return [b.subarray(offset, offset + 4) as ReuseGuard, 4]
}

export const encodeSenderData: Encoder<SenderData> = contramapEncoders(
  [encodeUint32, encodeUint32, encodeReuseGuard],
  (s) => [s.leafIndex, s.generation, s.reuseGuard] as const,
)

export const decodeSenderData: Decoder<SenderData> = mapDecoders(
  [decodeUint32, decodeUint32, decodeReuseGuard],
  (leafIndex, generation, reuseGuard) => ({
    leafIndex,
    generation,
    reuseGuard,
  }),
)

export interface SenderDataAAD {
  groupId: Uint8Array
  epoch: bigint
  contentType: ContentTypeName
}

export const encodeSenderDataAAD: Encoder<SenderDataAAD> = contramapEncoders(
  [encodeVarLenData, encodeUint64, encodeContentType],
  (aad) => [aad.groupId, aad.epoch, aad.contentType] as const,
)

export const decodeSenderDataAAD: Decoder<SenderDataAAD> = mapDecoders(
  [decodeVarLenData, decodeUint64, decodeContentType],
  (groupId, epoch, contentType) => ({
    groupId,
    epoch,
    contentType,
  }),
)

export function sampleCiphertext(cs: CiphersuiteImpl, ciphertext: Uint8Array): Uint8Array {
  return ciphertext.length < cs.kdf.size ? ciphertext : ciphertext.slice(0, cs.kdf.size)
}

export async function expandSenderDataKey(
  cs: CiphersuiteImpl,
  senderDataSecret: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const ciphertextSample = sampleCiphertext(cs, ciphertext)
  const keyLength = cs.hpke.keyLength

  return await expandWithLabel(senderDataSecret, "key", ciphertextSample, keyLength, cs.kdf)
}

export async function expandSenderDataNonce(
  cs: CiphersuiteImpl,
  senderDataSecret: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const ciphertextSample = sampleCiphertext(cs, ciphertext)
  const keyLength = cs.hpke.nonceLength

  return await expandWithLabel(senderDataSecret, "nonce", ciphertextSample, keyLength, cs.kdf)
}
