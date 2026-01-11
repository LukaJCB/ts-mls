import { decodeUint32, decodeUint64, decodeUint8, uint32Encoder, uint64Encoder, uint8Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { ContentTypeValue, contentTypeEncoder, decodeContentType } from "./contentType.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { expandWithLabel } from "./crypto/kdf.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

/** @public */
export const senderTypes = {
  member: 1,
  external: 2,
  new_member_proposal: 3,
  new_member_commit: 4,
} as const

/** @public */
export type SenderTypeName = keyof typeof senderTypes
export type SenderTypeValue = (typeof senderTypes)[SenderTypeName]

export const senderTypeEncoder: BufferEncoder<SenderTypeName> = contramapBufferEncoder(
  uint8Encoder,
  (t) => senderTypes[t],
)

export const encodeSenderType: Encoder<SenderTypeName> = encode(senderTypeEncoder)

export const decodeSenderType: Decoder<SenderTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(senderTypes))

/** @public */
export interface SenderMember {
  senderType: "member"
  leafIndex: number
}

/** @public */
export type SenderNonMember = SenderExternal | SenderNewMemberProposal | SenderNewMemberCommit

/** @public */
export interface SenderExternal {
  senderType: "external"
  senderIndex: number
}

/** @public */
export interface SenderNewMemberProposal {
  senderType: "new_member_proposal"
}

/** @public */
export interface SenderNewMemberCommit {
  senderType: "new_member_commit"
}

/** @public */
export type Sender = SenderMember | SenderNonMember

export const senderEncoder: BufferEncoder<Sender> = (s) => {
  switch (s.senderType) {
    case "member":
      return contramapBufferEncoders(
        [senderTypeEncoder, uint32Encoder],
        (s: SenderMember) => [s.senderType, s.leafIndex] as const,
      )(s)
    case "external":
      return contramapBufferEncoders(
        [senderTypeEncoder, uint32Encoder],
        (s: SenderExternal) => [s.senderType, s.senderIndex] as const,
      )(s)
    case "new_member_proposal":
    case "new_member_commit":
      return senderTypeEncoder(s.senderType)
  }
}

export const encodeSender: Encoder<Sender> = encode(senderEncoder)

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

export const reuseGuardEncoder: BufferEncoder<ReuseGuard> = (g) => [
  4,
  (offset, buffer) => {
    const view = new Uint8Array(buffer, offset, 4)
    view.set(g, 0)
  },
]

export const encodeReuseGuard: Encoder<ReuseGuard> = encode(reuseGuardEncoder)

export const decodeReuseGuard: Decoder<ReuseGuard> = (b, offset) => {
  return [b.subarray(offset, offset + 4) as ReuseGuard, 4]
}

export const senderDataEncoder: BufferEncoder<SenderData> = contramapBufferEncoders(
  [uint32Encoder, uint32Encoder, reuseGuardEncoder],
  (s) => [s.leafIndex, s.generation, s.reuseGuard] as const,
)

export const encodeSenderData: Encoder<SenderData> = encode(senderDataEncoder)

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
  contentType: ContentTypeValue
}

export const senderDataAADEncoder: BufferEncoder<SenderDataAAD> = contramapBufferEncoders(
  [varLenDataEncoder, uint64Encoder, contentTypeEncoder],
  (aad) => [aad.groupId, aad.epoch, aad.contentType] as const,
)

export const encodeSenderDataAAD: Encoder<SenderDataAAD> = encode(senderDataAADEncoder)

export const decodeSenderDataAAD: Decoder<SenderDataAAD> = mapDecoders(
  [decodeVarLenData, decodeUint64, decodeContentType],
  (groupId, epoch, contentType) => ({
    groupId,
    epoch,
    contentType,
  }),
)

export function sampleCiphertext(cs: CiphersuiteImpl, ciphertext: Uint8Array): Uint8Array {
  return ciphertext.length < cs.kdf.size ? ciphertext : ciphertext.subarray(0, cs.kdf.size)
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
