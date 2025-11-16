import { decodeUint16, encUint16 } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapEnc, Enc } from "./codec/tlsEncoder.js"
import { openEnumNumberEncoder, openEnumNumberToKey } from "./util/enumHelpers.js"

const credentialTypes = {
  basic: 1,
  x509: 2,
} as const

export type CredentialTypeName = keyof typeof credentialTypes
export type CredentialTypeValue = (typeof credentialTypes)[CredentialTypeName]

export const encodeCredentialType: Enc<CredentialTypeName> = contramapEnc(
  encUint16,
  openEnumNumberEncoder(credentialTypes),
)

export const decodeCredentialType: Decoder<CredentialTypeName> = mapDecoderOption(
  decodeUint16,
  openEnumNumberToKey(credentialTypes),
)
