import { decodeUint16, encodeUint16 } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapEncoder, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

export const defaultProposalTypes = {
  add: 1,
  update: 2,
  remove: 3,
  psk: 4,
  reinit: 5,
  external_init: 6,
  group_context_extensions: 7,
} as const

export type DefaultProposalTypeName = keyof typeof defaultProposalTypes
export type DefaultProposalTypeValue = (typeof defaultProposalTypes)[DefaultProposalTypeName]

export const encodeDefaultProposalType: Encoder<DefaultProposalTypeName> = contramapEncoder(
  encodeUint16,
  (n) => defaultProposalTypes[n],
)

export const decodeDefaultProposalType: Decoder<DefaultProposalTypeName> = mapDecoderOption(
  decodeUint16,
  enumNumberToKey(defaultProposalTypes),
)
