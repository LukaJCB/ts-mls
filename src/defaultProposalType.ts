import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { BufferEncoder } from "./codec/tlsEncoder.js"

/** @public */
export const defaultProposalTypes = {
  add: 1,
  update: 2,
  remove: 3,
  psk: 4,
  reinit: 5,
  external_init: 6,
  group_context_extensions: 7,
} as const

/** @public */
export type DefaultProposalTypeName = keyof typeof defaultProposalTypes
export type DefaultProposalTypeValue = (typeof defaultProposalTypes)[DefaultProposalTypeName]

const defaultProposalTypeValues = new Set<number>(Object.values(defaultProposalTypes))

export function isDefaultProposalTypeValue(v: number): v is DefaultProposalTypeValue {
  return defaultProposalTypeValues.has(v)
}

export const defaultProposalTypeValueEncoder: BufferEncoder<DefaultProposalTypeValue> = uint16Encoder

export const decodeDefaultProposalTypeValue: Decoder<DefaultProposalTypeValue> = mapDecoderOption(decodeUint16, (v) =>
  defaultProposalTypeValues.has(v) ? (v as DefaultProposalTypeValue) : undefined,
)
