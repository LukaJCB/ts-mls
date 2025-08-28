import { decodeUint16, encodeUint16 } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapEncoder, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

export const defaultExtensionTypes = {
  application_id: 1,
  ratchet_tree: 2,
  required_capabilities: 3,
  external_pub: 4,
  external_senders: 5,
} as const

export type DefaultExtensionTypeName = keyof typeof defaultExtensionTypes
export type DefaultExtensionTypeValue = (typeof defaultExtensionTypes)[DefaultExtensionTypeName]

export const encodeDefaultExtensionType: Encoder<DefaultExtensionTypeName> = contramapEncoder(
  encodeUint16,
  (n) => defaultExtensionTypes[n],
)

export const decodeDefaultExtensionType: Decoder<DefaultExtensionTypeName> = mapDecoderOption(
  decodeUint16,
  enumNumberToKey(defaultExtensionTypes),
)
