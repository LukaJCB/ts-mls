import { decodeUint16, encUint16 } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapEnc, Enc } from "./codec/tlsEncoder.js"
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

export const encodeWireformat: Enc<WireformatName> = (s) =>
  contramapEnc(encUint16, (t: WireformatName) => wireformats[t])(s)

export const decodeWireformat: Decoder<WireformatName> = mapDecoderOption(decodeUint16, enumNumberToKey(wireformats))
