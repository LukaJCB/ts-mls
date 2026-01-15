import { ciphersuiteEncoder, CiphersuiteId, ciphersuiteDecoder } from "./crypto/ciphersuite.js"
import { protocolVersionDecoder, protocolVersionEncoder, ProtocolVersionValue } from "./protocolVersion.js"
import { Encoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { varLenTypeDecoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { uint16Decoder, uint16Encoder } from "./codec/number.js"

/** @public */
export interface Capabilities {
  versions: ProtocolVersionValue[]
  ciphersuites: CiphersuiteId[]
  extensions: number[]
  proposals: number[]
  credentials: number[]
}

export const capabilitiesEncoder: Encoder<Capabilities> = contramapBufferEncoders(
  [
    varLenTypeEncoder(protocolVersionEncoder),
    varLenTypeEncoder(ciphersuiteEncoder),
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(uint16Encoder),
  ],
  (cap) => [cap.versions, cap.ciphersuites, cap.extensions, cap.proposals, cap.credentials] as const,
)

export const capabilitiesDecoder: Decoder<Capabilities> = mapDecoders(
  [
    varLenTypeDecoder(protocolVersionDecoder),
    varLenTypeDecoder(ciphersuiteDecoder),
    varLenTypeDecoder(uint16Decoder),
    varLenTypeDecoder(uint16Decoder),
    varLenTypeDecoder(uint16Decoder),
  ],
  (versions, ciphersuites, extensions, proposals, credentials) => ({
    versions,
    ciphersuites,
    extensions,
    proposals,
    credentials,
  }),
)
