import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { numberToEnum } from "./util/enumHelpers.js"

/** @public */
export const wireformats = {
  mls_public_message: 1,
  mls_private_message: 2,
  mls_welcome: 3,
  mls_group_info: 4,
  mls_key_package: 5,
} as const

/** @public */
export type WireformatName = keyof typeof wireformats
/** @public */
export type WireformatValue = (typeof wireformats)[WireformatName]

export const wireformatEncoder: BufferEncoder<WireformatValue> = uint16Encoder

export const encodeWireformat: Encoder<WireformatValue> = encode(wireformatEncoder)

export const decodeWireformat: Decoder<WireformatValue> = mapDecoderOption(decodeUint16, numberToEnum(wireformats))
