import { Decoder, flatMapDecoder, mapDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import {
  CredentialTypeValue,
  decodeCredentialTypeName,
  credentialTypeEncoder,
  credentialTypeNameEncoder,
} from "./credentialType.js"

/** @public */
export type Credential = CredentialBasic | CredentialX509 | CredentialCustom

/** @public */
export interface CredentialBasic {
  credentialType: "basic"
  identity: Uint8Array
}

/** @public */
export interface CredentialX509 {
  credentialType: "x509"
  certificates: Uint8Array[]
}

/** @public */
export interface CredentialCustom {
  credentialType: CredentialTypeValue
  data: Uint8Array
}

export const credentialBasicEncoder: BufferEncoder<CredentialBasic> = contramapBufferEncoders(
  [credentialTypeNameEncoder, varLenDataEncoder],
  (c) => [c.credentialType, c.identity] as const,
)

export const encodeCredentialBasic: Encoder<CredentialBasic> = encode(credentialBasicEncoder)

export const credentialX509Encoder: BufferEncoder<CredentialX509> = contramapBufferEncoders(
  [credentialTypeNameEncoder, varLenTypeEncoder(varLenDataEncoder)],
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
      return credentialCustomEncoder(c)
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
  decodeCredentialTypeName,
  (credentialType): Decoder<Credential> => {
    switch (credentialType) {
      case "basic":
        return decodeCredentialBasic
      case "x509":
        return decodeCredentialX509
    }
  },
)
