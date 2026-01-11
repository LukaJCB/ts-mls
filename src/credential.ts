import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import {
  defaultCredentialTypeValueEncoder,
  defaultCredentialTypes,
  isDefaultCredentialTypeValue,
} from "./defaultCredentialType.js"

/** @public */
export type Credential = DefaultCredential | CredentialCustom

/** @public */
export type DefaultCredential = CredentialBasic | CredentialX509

/** @public */
export interface CredentialBasic {
  credentialType: typeof defaultCredentialTypes.basic
  identity: Uint8Array
}

/** @public */
export interface CredentialX509 {
  credentialType: typeof defaultCredentialTypes.x509
  certificates: Uint8Array[]
}

/** @public */
export interface CredentialCustom {
  credentialType: number
  data: Uint8Array
}

export function isDefaultCredential(c: Credential): c is DefaultCredential {
  return isDefaultCredentialTypeValue(c.credentialType)
}

export const credentialBasicEncoder: BufferEncoder<CredentialBasic> = contramapBufferEncoders(
  [defaultCredentialTypeValueEncoder, varLenDataEncoder],
  (c) => [c.credentialType, c.identity] as const,
)

export const encodeCredentialBasic: Encoder<CredentialBasic> = encode(credentialBasicEncoder)

export const credentialX509Encoder: BufferEncoder<CredentialX509> = contramapBufferEncoders(
  [defaultCredentialTypeValueEncoder, varLenTypeEncoder(varLenDataEncoder)],
  (c) => [c.credentialType, c.certificates] as const,
)

export const encodeCredentialX509: Encoder<CredentialX509> = encode(credentialX509Encoder)

export const credentialCustomEncoder: BufferEncoder<CredentialCustom> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (c) => [c.credentialType, c.data] as const,
)

export const encodeCredentialCustom: Encoder<CredentialCustom> = encode(credentialCustomEncoder)

export const credentialEncoder: BufferEncoder<Credential> = (c) => {
  if (!isDefaultCredential(c)) return credentialCustomEncoder(c)

  switch (c.credentialType) {
    case defaultCredentialTypes.basic:
      return credentialBasicEncoder(c)
    case defaultCredentialTypes.x509:
      return credentialX509Encoder(c)
  }
}

export const encodeCredential: Encoder<Credential> = encode(credentialEncoder)

const decodeCredentialBasic: Decoder<CredentialBasic> = mapDecoder(decodeVarLenData, (identity) => ({
  credentialType: defaultCredentialTypes.basic,
  identity,
}))

const decodeCredentialX509: Decoder<CredentialX509> = mapDecoder(
  decodeVarLenType(decodeVarLenData),
  (certificates) => ({ credentialType: defaultCredentialTypes.x509, certificates }),
)

function decodeCredentialCustom(credentialType: number): Decoder<CredentialCustom> {
  return mapDecoder(decodeVarLenData, (data) => ({ credentialType, data }))
}

export const decodeCredential: Decoder<Credential> = flatMapDecoder(
  decodeUint16,
  (credentialType): Decoder<Credential> => {
    switch (credentialType) {
      case defaultCredentialTypes.basic:
        return decodeCredentialBasic
      case defaultCredentialTypes.x509:
        return decodeCredentialX509
      default:
        return decodeCredentialCustom(credentialType)
    }
  },
)
