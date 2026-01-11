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
export type CredentialTypeValue = (typeof credentialTypes)[CredentialTypeName]

export const credentialTypeEncoder: BufferEncoder<CredentialTypeName> = contramapBufferEncoder(
  uint16Encoder,
  openEnumNumberEncoder(credentialTypes),
)

export const encodeCredentialType: Encoder<CredentialTypeName> = encode(credentialTypeEncoder)

export const decodeCredentialType: Decoder<CredentialTypeName> = mapDecoderOption(
  decodeUint16,
  openEnumNumberToKey(credentialTypes),
)
