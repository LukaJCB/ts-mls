import { Decoder, flatMapDecoder, mapDecoder } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { CredentialTypeName, decodeCredentialType, encodeCredentialType } from "./credentialType"

export type Credential = CredentialBasic | CredentialX509

export interface CredentialBasic {
  credentialType: "basic"
  identity: Uint8Array
}
export interface CredentialX509 {
  credentialType: "x509"
  certificates: Uint8Array[]
}

export interface CredentialCustom {
  credentialType: CredentialTypeName
  data: Uint8Array
}

export const encodeCredentialBasic: Encoder<CredentialBasic> = contramapEncoders(
  [encodeCredentialType, encodeVarLenData],
  (c) => [c.credentialType, c.identity] as const,
)

export const encodeCredentialX509: Encoder<CredentialX509> = contramapEncoders(
  [encodeCredentialType, encodeVarLenType(encodeVarLenData)],
  (c) => [c.credentialType, c.certificates] as const,
)

export const encodeCredentialCustom: Encoder<CredentialCustom> = contramapEncoders(
  [encodeCredentialType, encodeVarLenData],
  (c) => [c.credentialType, c.data] as const,
)

export const encodeCredential: Encoder<Credential> = (c) => {
  switch (c.credentialType) {
    case "basic":
      return encodeCredentialBasic(c)
    case "x509":
      return encodeCredentialX509(c)
    default:
      return encodeCredentialCustom(c as CredentialCustom)
  }
}

const decodeCredentialBasic: Decoder<CredentialBasic> = mapDecoder(decodeVarLenData, (identity) => ({
  credentialType: "basic",
  identity,
}))

const decodeCredentialX509: Decoder<CredentialX509> = mapDecoder(
  decodeVarLenType(decodeVarLenData),
  (certificates) => ({ credentialType: "x509", certificates }),
)

export const decodeCredential: Decoder<Credential> = flatMapDecoder(
  decodeCredentialType,
  (credentialType): Decoder<Credential> => {
    switch (credentialType) {
      case "basic":
        return decodeCredentialBasic
      case "x509":
        return decodeCredentialX509
    }
  },
)
