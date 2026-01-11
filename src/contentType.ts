import { decodeUint8, uint8Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { numberToEnum } from "./util/enumHelpers.js"

/** @public */
export const contentTypes = {
  application: 1,
  proposal: 2,
  commit: 3,
} as const

/** @public */
export type ContentTypeName = keyof typeof contentTypes
/** @public */
export type ContentTypeValue = (typeof contentTypes)[ContentTypeName]

export const contentTypeEncoder: BufferEncoder<ContentTypeValue> = uint8Encoder

export const encodeContentType: Encoder<ContentTypeValue> = encode(contentTypeEncoder)

export const decodeContentType: Decoder<ContentTypeValue> = mapDecoderOption(decodeUint8, numberToEnum(contentTypes))
