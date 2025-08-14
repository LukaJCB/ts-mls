import { CredentialTypeName, encodeCredentialType, decodeCredentialType } from "./credentialType"
import { encodeVarLenType, decodeVarLenType } from "./codec/variableLength"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { decodeUint16, encodeUint16 } from "./codec/number"

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
