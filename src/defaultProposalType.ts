import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

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

export const defaultProposalTypeEncoder: BufferEncoder<DefaultProposalTypeName> = contramapBufferEncoder(
  uint16Encoder,
  (n) => defaultProposalTypes[n],
)

export const encodeDefaultProposalType: Encoder<DefaultProposalTypeName> = encode(defaultProposalTypeEncoder)

export const decodeDefaultProposalType: Decoder<DefaultProposalTypeName> = mapDecoderOption(
  decodeUint16,
  enumNumberToKey(defaultProposalTypes),
)
