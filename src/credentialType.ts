import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { openEnumNumberEncoder, openEnumNumberToKey } from "./util/enumHelpers.js"

/** @public */
export const credentialTypes = {
  basic: 1,
  x509: 2,
} as const

/** @public */
export type CredentialTypeName = keyof typeof credentialTypes
/** @public */
export type CredentialTypeValue = (typeof credentialTypes)[CredentialTypeName]

export function credentialTypeValueFromName(name: CredentialTypeName): CredentialTypeValue {
  return openEnumNumberEncoder(credentialTypes)(name) as CredentialTypeValue
}

export const credentialTypeEncoder: BufferEncoder<CredentialTypeValue> = uint16Encoder

export const encodeCredentialType: Encoder<CredentialTypeValue> = encode(credentialTypeEncoder)

export const decodeCredentialType: Decoder<CredentialTypeValue> = (b, offset) => {
  const decoded = decodeUint16(b, offset)
  return decoded === undefined ? undefined : [decoded[0] as CredentialTypeValue, decoded[1]]
}

export const credentialTypeNameEncoder: BufferEncoder<CredentialTypeName> = contramapBufferEncoder(
  uint16Encoder,
  openEnumNumberEncoder(credentialTypes),
)

export const encodeCredentialTypeName: Encoder<CredentialTypeName> = encode(credentialTypeNameEncoder)

export const decodeCredentialTypeName: Decoder<CredentialTypeName> = mapDecoderOption(
  decodeUint16,
  openEnumNumberToKey(credentialTypes),
)
