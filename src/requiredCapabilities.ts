import { CredentialTypeName, encodeCredentialType, decodeCredentialType } from "./credentialType"
import { ExtensionTypeName, encodeExtensionType, decodeExtensionType } from "./extensionType"
import { ProposalTypeName, encodeProposalType, decodeProposalType } from "./proposalType"
import { encodeVarLenType, decodeVarLenType } from "./codec/variableLength"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"

export type RequiredCapabilities = {
  extensionTypes: ExtensionTypeName[]
  proposalTypes: ProposalTypeName[]
  credentialTypes: CredentialTypeName[]
}

export const encodeRequiredCapabilities: Encoder<RequiredCapabilities> = contramapEncoders(
  [encodeVarLenType(encodeExtensionType), encodeVarLenType(encodeProposalType), encodeVarLenType(encodeCredentialType)],
  (rc) => [rc.extensionTypes, rc.proposalTypes, rc.credentialTypes] as const,
)

export const decodeRequiredCapabilities: Decoder<RequiredCapabilities> = mapDecoders(
  [decodeVarLenType(decodeExtensionType), decodeVarLenType(decodeProposalType), decodeVarLenType(decodeCredentialType)],
  (extensionTypes, proposalTypes, credentialTypes) => ({ extensionTypes, proposalTypes, credentialTypes }),
)
