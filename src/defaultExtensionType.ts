import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
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

export const defaultExtensionTypeEncoder: BufferEncoder<DefaultExtensionTypeName> = contramapBufferEncoder(
  uint16Encoder,
  (n) => defaultExtensionTypes[n],
)

export const encodeDefaultExtensionType: Encoder<DefaultExtensionTypeName> = encode(defaultExtensionTypeEncoder)

export const decodeDefaultExtensionType: Decoder<DefaultExtensionTypeName> = mapDecoderOption(
  decodeUint16,
  enumNumberToKey(defaultExtensionTypes),
)
