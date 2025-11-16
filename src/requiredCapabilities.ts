import { CredentialTypeName, encodeCredentialType, decodeCredentialType } from "./credentialType.js"
import { encVarLenType, decodeVarLenType } from "./codec/variableLength.js"
import { Enc, contramapEncs } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { decodeUint16, encUint16 } from "./codec/number.js"

export interface RequiredCapabilities {
  extensionTypes: number[]
  proposalTypes: number[]
  credentialTypes: CredentialTypeName[]
}

export const encodeRequiredCapabilities: Enc<RequiredCapabilities> = contramapEncs(
  [encVarLenType(encUint16), encVarLenType(encUint16), encVarLenType(encodeCredentialType)],
  (rc) => [rc.extensionTypes, rc.proposalTypes, rc.credentialTypes] as const,
)

export const decodeRequiredCapabilities: Decoder<RequiredCapabilities> = mapDecoders(
  [decodeVarLenType(decodeUint16), decodeVarLenType(decodeUint16), decodeVarLenType(decodeCredentialType)],
  (extensionTypes, proposalTypes, credentialTypes) => ({ extensionTypes, proposalTypes, credentialTypes }),
)
