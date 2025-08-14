import { CredentialTypeName, decodeCredentialType, encodeCredentialType } from "./credentialType"
import { CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { decodeVarLenType, encodeVarLenType } from "./codec/variableLength"
import { decodeUint16, encodeUint16 } from "./codec/number"

export interface Capabilities {
  versions: ProtocolVersionName[]
  ciphersuites: CiphersuiteName[]
  extensions: number[]
  proposals: number[]
  credentials: CredentialTypeName[]
}

export const encodeCapabilities: Encoder<Capabilities> = contramapEncoders(
  [
    encodeVarLenType(encodeProtocolVersion),
    encodeVarLenType(encodeCiphersuite),
    encodeVarLenType(encodeUint16),
    encodeVarLenType(encodeUint16),
    encodeVarLenType(encodeCredentialType),
  ],
  (cap) => [cap.versions, cap.ciphersuites, cap.extensions, cap.proposals, cap.credentials] as const,
)

export const decodeCapabilities: Decoder<Capabilities> = mapDecoders(
  [
    decodeVarLenType(decodeProtocolVersion),
    decodeVarLenType(decodeCiphersuite),
    decodeVarLenType(decodeUint16),
    decodeVarLenType(decodeUint16),
    decodeVarLenType(decodeCredentialType),
  ],
  (versions, ciphersuites, extensions, proposals, credentials) => ({
    versions,
    ciphersuites,
    extensions,
    proposals,
    credentials,
  }),
)
