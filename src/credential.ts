import { uint16Decoder, uint16Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenTypeDecoder, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { defaultCredentialTypes, isDefaultCredentialTypeValue } from "./defaultCredentialType.js"

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

/** @public */
export function isDefaultCredential(c: Credential): c is DefaultCredential {
  return isDefaultCredentialTypeValue(c.credentialType)
}

export const credentialBasicEncoder: Encoder<CredentialBasic> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (c) => [c.credentialType, c.identity] as const,
)

export const credentialX509Encoder: Encoder<CredentialX509> = contramapBufferEncoders(
  [uint16Encoder, varLenTypeEncoder(varLenDataEncoder)],
  (c) => [c.credentialType, c.certificates] as const,
)

export const credentialCustomEncoder: Encoder<CredentialCustom> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (c) => [c.credentialType, c.data] as const,
)

export const credentialEncoder: Encoder<Credential> = (c) => {
  if (!isDefaultCredential(c)) return credentialCustomEncoder(c)

  switch (c.credentialType) {
    case defaultCredentialTypes.basic:
      return credentialBasicEncoder(c)
    case defaultCredentialTypes.x509:
      return credentialX509Encoder(c)
  }
}

const credentialBasicDecoder: Decoder<CredentialBasic> = mapDecoder(varLenDataDecoder, (identity) => ({
  credentialType: defaultCredentialTypes.basic,
  identity,
}))

const credentialX509Decoder: Decoder<CredentialX509> = mapDecoder(
  varLenTypeDecoder(varLenDataDecoder),
  (certificates) => ({ credentialType: defaultCredentialTypes.x509, certificates }),
)

function credentialCustomDecoder(credentialType: number): Decoder<CredentialCustom> {
  return mapDecoder(varLenDataDecoder, (data) => ({ credentialType, data }))
}

export const credentialDecoder: Decoder<Credential> = flatMapDecoder(
  uint16Decoder,
  (credentialType): Decoder<Credential> => {
    switch (credentialType) {
      case defaultCredentialTypes.basic:
        return credentialBasicDecoder
      case defaultCredentialTypes.x509:
        return credentialX509Decoder
      default:
        return credentialCustomDecoder(credentialType)
    }
  },
)
