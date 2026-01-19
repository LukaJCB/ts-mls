import { varLenTypeEncoder, varLenTypeDecoder } from "./codec/variableLength.js"
import { Encoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { uint16Decoder, uint16Encoder } from "./codec/number.js"

/** @public */
export interface RequiredCapabilities {
  extensionTypes: number[]
  proposalTypes: number[]
  credentialTypes: number[]
}

export const requiredCapabilitiesEncoder: Encoder<RequiredCapabilities> = contramapBufferEncoders(
  [varLenTypeEncoder(uint16Encoder), varLenTypeEncoder(uint16Encoder), varLenTypeEncoder(uint16Encoder)],
  (rc) => [rc.extensionTypes, rc.proposalTypes, rc.credentialTypes] as const,
)

export const requiredCapabilitiesDecoder: Decoder<RequiredCapabilities> = mapDecoders(
  [varLenTypeDecoder(uint16Decoder), varLenTypeDecoder(uint16Decoder), varLenTypeDecoder(uint16Decoder)],
  (extensionTypes, proposalTypes, credentialTypes) => ({ extensionTypes, proposalTypes, credentialTypes }),
)
