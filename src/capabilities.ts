import { ciphersuiteEncoder, CiphersuiteId, decodeCiphersuite } from "./crypto/ciphersuite.js"
import { decodeProtocolVersion, protocolVersionEncoder, ProtocolVersionValue } from "./protocolVersion.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { decodeVarLenType, varLenTypeEncoder } from "./codec/variableLength.js"
import { decodeUint16, uint16Encoder } from "./codec/number.js"

/** @public */
export interface Capabilities {
  versions: ProtocolVersionValue[]
  ciphersuites: CiphersuiteId[]
  extensions: number[]
  proposals: number[]
  credentials: number[]
}

export const capabilitiesEncoder: BufferEncoder<Capabilities> = contramapBufferEncoders(
  [
    varLenTypeEncoder(protocolVersionEncoder),
    varLenTypeEncoder(ciphersuiteEncoder),
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(uint16Encoder),
  ],
  (cap) => [cap.versions, cap.ciphersuites, cap.extensions, cap.proposals, cap.credentials] as const,
)

export const decodeCapabilities: Decoder<Capabilities> = mapDecoders(
  [
    decodeVarLenType(decodeProtocolVersion),
    decodeVarLenType(decodeCiphersuite),
    decodeVarLenType(decodeUint16),
    decodeVarLenType(decodeUint16),
    decodeVarLenType(decodeUint16),
  ],
  (versions, ciphersuites, extensions, proposals, credentials) => ({
    versions,
    ciphersuites,
    extensions,
    proposals,
    credentials,
  }),
)
