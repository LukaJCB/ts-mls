import { CredentialTypeName, decodeCredentialType, credentialTypeEncoder } from "./credentialType.js"
import { CiphersuiteId } from "./crypto/ciphersuite.js"
import { decodeProtocolVersion, protocolVersionEncoder, ProtocolVersionName } from "./protocolVersion.js"
import { BufferEncoder, contramapBufferEncoders, encode, Encoder } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { decodeVarLenType, varLenTypeEncoder } from "./codec/variableLength.js"
import { decodeUint16, uint16Encoder } from "./codec/number.js"

/** @public */
export interface Capabilities {
  versions: ProtocolVersionName[]
  ciphersuites: CiphersuiteId[]
  extensions: number[]
  proposals: number[]
  credentials: CredentialTypeName[]
}

export const capabilitiesEncoder: BufferEncoder<Capabilities> = contramapBufferEncoders(
  [
    varLenTypeEncoder(protocolVersionEncoder),
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(credentialTypeEncoder),
  ],
  (cap) => [cap.versions, cap.ciphersuites, cap.extensions, cap.proposals, cap.credentials] as const,
)

export const encodeCapabilities: Encoder<Capabilities> = encode(capabilitiesEncoder)

export const decodeCapabilities: Decoder<Capabilities> = mapDecoders(
  [
    decodeVarLenType(decodeProtocolVersion),
    decodeVarLenType(decodeUint16),
    decodeVarLenType(decodeUint16),
    decodeVarLenType(decodeUint16),
    decodeVarLenType(decodeCredentialType),
  ],
  (versions, ciphersuites, extensions, proposals, credentials) => ({
    versions,
    ciphersuites: ciphersuites as CiphersuiteId[],
    extensions,
    proposals,
    credentials,
  }),
)
