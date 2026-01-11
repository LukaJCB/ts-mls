import { CredentialTypeName, credentialTypeEncoder, decodeCredentialType } from "./credentialType.js"
import { varLenTypeEncoder, decodeVarLenType } from "./codec/variableLength.js"
import { BufferEncoder, contramapBufferEncoders, encode, Encoder } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { decodeUint16, uint16Encoder } from "./codec/number.js"

/** @public */
export interface RequiredCapabilities {
  extensionTypes: number[]
  proposalTypes: number[]
  credentialTypes: CredentialTypeName[]
}

export const requiredCapabilitiesEncoder: BufferEncoder<RequiredCapabilities> = contramapBufferEncoders(
  [varLenTypeEncoder(uint16Encoder), varLenTypeEncoder(uint16Encoder), varLenTypeEncoder(credentialTypeEncoder)],
  (rc) => [rc.extensionTypes, rc.proposalTypes, rc.credentialTypes] as const,
)

/** @public */
export const encodeRequiredCapabilities: Encoder<RequiredCapabilities> = encode(requiredCapabilitiesEncoder)

/** @public */
export const decodeRequiredCapabilities: Decoder<RequiredCapabilities> = mapDecoders(
  [decodeVarLenType(decodeUint16), decodeVarLenType(decodeUint16), decodeVarLenType(decodeCredentialType)],
  (extensionTypes, proposalTypes, credentialTypes) => ({ extensionTypes, proposalTypes, credentialTypes }),
)
