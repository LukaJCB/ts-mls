import { decodeUint8, uint8Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

const contentTypes = {
  application: 1,
  proposal: 2,
  commit: 3,
} as const

export type ContentTypeName = keyof typeof contentTypes
export type ContentTypeValue = (typeof contentTypes)[ContentTypeName]

export const contentTypeEncoder: BufferEncoder<ContentTypeName> = contramapBufferEncoder(
  uint8Encoder,
  (t) => contentTypes[t],
)

export const encodeContentType: Encoder<ContentTypeName> = encode(contentTypeEncoder)

export const decodeContentType: Decoder<ContentTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(contentTypes))
