import { CredentialTypeName, encodeCredentialType, decodeCredentialType } from "./credentialType.js"
import { encodeVarLenType, decodeVarLenType } from "./codec/variableLength.js"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { decodeUint16, encodeUint16 } from "./codec/number.js"

export interface RequiredCapabilities {
  extensionTypes: number[]
  proposalTypes: number[]
  credentialTypes: CredentialTypeName[]
}

export const encodeRequiredCapabilities: Encoder<RequiredCapabilities> = contramapEncoders(
  [encodeVarLenType(encodeUint16), encodeVarLenType(encodeUint16), encodeVarLenType(encodeCredentialType)],
  (rc) => [rc.extensionTypes, rc.proposalTypes, rc.credentialTypes] as const,
)

export const decodeRequiredCapabilities: Decoder<RequiredCapabilities> = mapDecoders(
  [decodeVarLenType(decodeUint16), decodeVarLenType(decodeUint16), decodeVarLenType(decodeCredentialType)],
  (extensionTypes, proposalTypes, credentialTypes) => ({ extensionTypes, proposalTypes, credentialTypes }),
)
