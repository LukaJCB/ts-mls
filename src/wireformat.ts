import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

export const wireformats = {
  mls_public_message: 1,
  mls_private_message: 2,
  mls_welcome: 3,
  mls_group_info: 4,
  mls_key_package: 5,
} as const

export type WireformatName = keyof typeof wireformats
export type WireformatValue = (typeof wireformats)[WireformatName]

export const wireformatEncoder: BufferEncoder<WireformatName> = (s) =>
  contramapBufferEncoder(uint16Encoder, (t: WireformatName) => wireformats[t])(s)

export const encodeWireformat: Encoder<WireformatName> = encode(wireformatEncoder)

export const decodeWireformat: Decoder<WireformatName> = mapDecoderOption(decodeUint16, enumNumberToKey(wireformats))
