import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

/** @public */
export const defaultCredentialTypes = {
  basic: 1,
  x509: 2,
} as const

/** @public */
export type DefaultCredentialTypeName = keyof typeof defaultCredentialTypes
/** @public */
export type DefaultCredentialTypeValue = (typeof defaultCredentialTypes)[DefaultCredentialTypeName]

const defaultCredentialTypeValues = new Set<number>(Object.values(defaultCredentialTypes))

export function defaultCredentialTypeValueFromName(name: DefaultCredentialTypeName): DefaultCredentialTypeValue {
  return defaultCredentialTypes[name]
}

export function isDefaultCredentialTypeValue(v: number): v is DefaultCredentialTypeValue {
  return defaultCredentialTypeValues.has(v)
}

export const defaultCredentialTypeValueEncoder: BufferEncoder<DefaultCredentialTypeValue> = uint16Encoder

export const encodeDefaultCredentialTypeValue: Encoder<DefaultCredentialTypeValue> = encode(
  defaultCredentialTypeValueEncoder,
)

export const decodeDefaultCredentialTypeValue: Decoder<DefaultCredentialTypeValue> = mapDecoderOption(
  decodeUint16,
  (v) => (defaultCredentialTypeValues.has(v) ? (v as DefaultCredentialTypeValue) : undefined),
)

export const defaultCredentialTypeEncoder: BufferEncoder<DefaultCredentialTypeName> = contramapBufferEncoder(
  uint16Encoder,
  (n) => defaultCredentialTypes[n],
)

export const encodeDefaultCredentialType: Encoder<DefaultCredentialTypeName> = encode(defaultCredentialTypeEncoder)

export const decodeDefaultCredentialType: Decoder<DefaultCredentialTypeName> = mapDecoderOption(
  decodeUint16,
  enumNumberToKey(defaultCredentialTypes),
)
