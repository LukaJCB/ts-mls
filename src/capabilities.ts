import { Encoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { varLenTypeDecoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { uint16Decoder, uint16Encoder } from "./codec/number.js"

/** @public */
export interface Capabilities {
  versions: number[]
  ciphersuites: number[]
  extensions: number[]
  proposals: number[]
  credentials: number[]
}

export const capabilitiesEncoder: Encoder<Capabilities> = contramapBufferEncoders(
  [
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(uint16Encoder),
    varLenTypeEncoder(uint16Encoder),
  ],
  (cap) => [cap.versions, cap.ciphersuites, cap.extensions, cap.proposals, cap.credentials] as const,
)

export const capabilitiesDecoder: Decoder<Capabilities> = mapDecoders(
  [
    varLenTypeDecoder(uint16Decoder),
    varLenTypeDecoder(uint16Decoder),
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
