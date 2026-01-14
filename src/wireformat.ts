import { uint16Decoder, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { Encoder } from "./codec/tlsEncoder.js"
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

export const wireformatEncoder: Encoder<WireformatValue> = uint16Encoder

export const wireformatDecoder: Decoder<WireformatValue> = mapDecoderOption(uint16Decoder, numberToEnum(wireformats))
