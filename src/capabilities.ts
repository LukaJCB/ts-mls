import { CredentialTypeName, decodeCredentialType, encodeCredentialType } from "./credentialType.js"
import { CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite.js"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion.js"
import { Enc, contramapEncs } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { decodeVarLenType, encVarLenType } from "./codec/variableLength.js"
import { decodeUint16, encUint16 } from "./codec/number.js"

export interface Capabilities {
  versions: ProtocolVersionName[]
  ciphersuites: CiphersuiteName[]
  extensions: number[]
  proposals: number[]
  credentials: CredentialTypeName[]
}

export const encodeCapabilities: Enc<Capabilities> = contramapEncs(
  [
    encVarLenType(encodeProtocolVersion),
    encVarLenType(encodeCiphersuite),
    encVarLenType(encUint16),
    encVarLenType(encUint16),
    encVarLenType(encodeCredentialType),
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
