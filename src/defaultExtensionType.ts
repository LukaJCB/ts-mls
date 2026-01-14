import { decodeUint16 } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"

/** @public */
export const defaultExtensionTypes = {
  application_id: 1,
  ratchet_tree: 2,
  required_capabilities: 3,
  external_pub: 4,
  external_senders: 5,
} as const

/** @public */
export type DefaultExtensionTypeName = keyof typeof defaultExtensionTypes
export type DefaultExtensionTypeValue = (typeof defaultExtensionTypes)[DefaultExtensionTypeName]

export function isDefaultExtensionTypeValue(v: number): v is DefaultExtensionTypeValue {
  return Object.values(defaultExtensionTypes).includes(v as DefaultExtensionTypeValue)
}

export const decodeDefaultExtensionTypeValue: Decoder<DefaultExtensionTypeValue> = mapDecoderOption(
  decodeUint16,
  (n) => (isDefaultExtensionTypeValue(n) ? n : undefined),
)