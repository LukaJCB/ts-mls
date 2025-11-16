import { Decoder, flatMapDecoder, mapDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CredentialTypeName, decodeCredentialType, credentialTypeEncoder } from "./credentialType.js"

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

export const credentialBasicEncoder: BufferEncoder<CredentialBasic> = contramapBufferEncoders(
  [credentialTypeEncoder, varLenDataEncoder],
  (c) => [c.credentialType, c.identity] as const,
)

export const encodeCredentialBasic: Encoder<CredentialBasic> = encode(credentialBasicEncoder)

export const credentialX509Encoder: BufferEncoder<CredentialX509> = contramapBufferEncoders(
  [credentialTypeEncoder, varLenTypeEncoder(varLenDataEncoder)],
  (c) => [c.credentialType, c.certificates] as const,
)

export const encodeCredentialX509: Encoder<CredentialX509> = encode(credentialX509Encoder)

export const credentialCustomEncoder: BufferEncoder<CredentialCustom> = contramapBufferEncoders(
  [credentialTypeEncoder, varLenDataEncoder],
  (c) => [c.credentialType, c.data] as const,
)

export const encodeCredentialCustom: Encoder<CredentialCustom> = encode(credentialCustomEncoder)

export const credentialEncoder: BufferEncoder<Credential> = (c) => {
  switch (c.credentialType) {
    case "basic":
      return credentialBasicEncoder(c)
    case "x509":
      return credentialX509Encoder(c)
    default:
      return credentialCustomEncoder(c as CredentialCustom)
  }
}

export const encodeCredential: Encoder<Credential> = encode(credentialEncoder)

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
