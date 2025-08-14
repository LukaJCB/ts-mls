import { decodeUint16, decodeUint32, encodeUint16, encodeUint32 } from "./codec/number"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, orDecoder } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite"
import { decodeExtension, encodeExtension, Extension } from "./extension"
import { decodeKeyPackage, encodeKeyPackage, KeyPackage } from "./keyPackage"
import { decodePskId, encodePskId, PreSharedKeyID } from "./presharedkey"
import { decodeDefaultProposalType, encodeDefaultProposalType } from "./defaultProposalType"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion"
import { decodeLeafNodeUpdate, encodeLeafNode, LeafNodeUpdate } from "./leafNode"

export interface Add {
  keyPackage: KeyPackage
}

export const encodeAdd: Encoder<Add> = contramapEncoder(encodeKeyPackage, (a) => a.keyPackage)
export const decodeAdd: Decoder<Add> = mapDecoder(decodeKeyPackage, (keyPackage) => ({ keyPackage }))

export interface Update {
  leafNode: LeafNodeUpdate
}

export const encodeUpdate: Encoder<Update> = contramapEncoder(encodeLeafNode, (u) => u.leafNode)
export const decodeUpdate: Decoder<Update> = mapDecoder(decodeLeafNodeUpdate, (leafNode) => ({ leafNode }))

export interface Remove {
  removed: number
}

export const encodeRemove: Encoder<Remove> = contramapEncoder(encodeUint32, (r) => r.removed)
export const decodeRemove: Decoder<Remove> = mapDecoder(decodeUint32, (removed) => ({ removed }))

export interface PSK {
  preSharedKeyId: PreSharedKeyID
}

export const encodePSK: Encoder<PSK> = contramapEncoder(encodePskId, (p) => p.preSharedKeyId)
export const decodePSK: Decoder<PSK> = mapDecoder(decodePskId, (preSharedKeyId) => ({ preSharedKeyId }))

export interface Reinit {
  groupId: Uint8Array
  version: ProtocolVersionName
  cipherSuite: CiphersuiteName
  extensions: Extension[]
}

export const encodeReinit: Encoder<Reinit> = contramapEncoders(
  [encodeVarLenData, encodeProtocolVersion, encodeCiphersuite, encodeVarLenType(encodeExtension)],
  (r) => [r.groupId, r.version, r.cipherSuite, r.extensions] as const,
)

export const decodeReinit: Decoder<Reinit> = mapDecoders(
  [decodeVarLenData, decodeProtocolVersion, decodeCiphersuite, decodeVarLenType(decodeExtension)],
  (groupId, version, cipherSuite, extensions) => ({ groupId, version, cipherSuite, extensions }),
)

export interface ExternalInit {
  kemOutput: Uint8Array
}

export const encodeExternalInit: Encoder<ExternalInit> = contramapEncoder(encodeVarLenData, (e) => e.kemOutput)
export const decodeExternalInit: Decoder<ExternalInit> = mapDecoder(decodeVarLenData, (kemOutput) => ({ kemOutput }))

export interface GroupContextExtensions {
  extensions: Extension[]
}

export const encodeGroupContextExtensions: Encoder<GroupContextExtensions> = contramapEncoder(
  encodeVarLenType(encodeExtension),
  (g) => g.extensions,
)

export const decodeGroupContextExtensions: Decoder<GroupContextExtensions> = mapDecoder(
  decodeVarLenType(decodeExtension),
  (extensions) => ({ extensions }),
)

export interface ProposalAdd {
  proposalType: "add"
  add: Add
}

export interface ProposalUpdate {
  proposalType: "update"
  update: Update
}

export interface ProposalRemove {
  proposalType: "remove"
  remove: Remove
}

export interface ProposalPSK {
  proposalType: "psk"
  psk: PSK
}

export interface ProposalReinit {
  proposalType: "reinit"
  reinit: Reinit
}

export interface ProposalExternalInit {
  proposalType: "external_init"
  externalInit: ExternalInit
}

export interface ProposalGroupContextExtensions {
  proposalType: "group_context_extensions"
  groupContextExtensions: GroupContextExtensions
}

export interface ProposalCustom {
  proposalType: number
  proposalData: Uint8Array
}

export type Proposal =
  | ProposalAdd
  | ProposalUpdate
  | ProposalRemove
  | ProposalPSK
  | ProposalReinit
  | ProposalExternalInit
  | ProposalGroupContextExtensions
  | ProposalCustom

export const encodeProposalAdd: Encoder<ProposalAdd> = contramapEncoders(
  [encodeDefaultProposalType, encodeAdd],
  (p) => [p.proposalType, p.add] as const,
)

export const encodeProposalUpdate: Encoder<ProposalUpdate> = contramapEncoders(
  [encodeDefaultProposalType, encodeUpdate],
  (p) => [p.proposalType, p.update] as const,
)

export const encodeProposalRemove: Encoder<ProposalRemove> = contramapEncoders(
  [encodeDefaultProposalType, encodeRemove],
  (p) => [p.proposalType, p.remove] as const,
)

export const encodeProposalPSK: Encoder<ProposalPSK> = contramapEncoders(
  [encodeDefaultProposalType, encodePSK],
  (p) => [p.proposalType, p.psk] as const,
)

export const encodeProposalReinit: Encoder<ProposalReinit> = contramapEncoders(
  [encodeDefaultProposalType, encodeReinit],
  (p) => [p.proposalType, p.reinit] as const,
)

export const encodeProposalExternalInit: Encoder<ProposalExternalInit> = contramapEncoders(
  [encodeDefaultProposalType, encodeExternalInit],
  (p) => [p.proposalType, p.externalInit] as const,
)

export const encodeProposalGroupContextExtensions: Encoder<ProposalGroupContextExtensions> = contramapEncoders(
  [encodeDefaultProposalType, encodeGroupContextExtensions],
  (p) => [p.proposalType, p.groupContextExtensions] as const,
)

export const encodeProposalCustom: Encoder<ProposalCustom> = contramapEncoders(
  [encodeUint16, encodeVarLenData],
  (p) => [p.proposalType, p.proposalData] as const,
)

export const encodeProposal: Encoder<Proposal> = (p) => {
  switch (p.proposalType) {
    case "add":
      return encodeProposalAdd(p)
    case "update":
      return encodeProposalUpdate(p)
    case "remove":
      return encodeProposalRemove(p)
    case "psk":
      return encodeProposalPSK(p)
    case "reinit":
      return encodeProposalReinit(p)
    case "external_init":
      return encodeProposalExternalInit(p)
    case "group_context_extensions":
      return encodeProposalGroupContextExtensions(p)
    default:
      return encodeProposalCustom(p)
  }
}

export const decodeProposalAdd: Decoder<ProposalAdd> = mapDecoder(decodeAdd, (add) => ({ proposalType: "add", add }))

export const decodeProposalUpdate: Decoder<ProposalUpdate> = mapDecoder(decodeUpdate, (update) => ({
  proposalType: "update",
  update,
}))

export const decodeProposalRemove: Decoder<ProposalRemove> = mapDecoder(decodeRemove, (remove) => ({
  proposalType: "remove",
  remove,
}))

export const decodeProposalPSK: Decoder<ProposalPSK> = mapDecoder(decodePSK, (psk) => ({ proposalType: "psk", psk }))

export const decodeProposalReinit: Decoder<ProposalReinit> = mapDecoder(decodeReinit, (reinit) => ({
  proposalType: "reinit",
  reinit,
}))

export const decodeProposalExternalInit: Decoder<ProposalExternalInit> = mapDecoder(
  decodeExternalInit,
  (externalInit) => ({ proposalType: "external_init", externalInit }),
)

export const decodeProposalGroupContextExtensions: Decoder<ProposalGroupContextExtensions> = mapDecoder(
  decodeGroupContextExtensions,
  (groupContextExtensions) => ({ proposalType: "group_context_extensions", groupContextExtensions }),
)

export function decodeProposalCustom(proposalType: number): Decoder<ProposalCustom> {
  return mapDecoder(decodeVarLenData, (proposalData) => ({ proposalType, proposalData }))
}

export const decodeProposal: Decoder<Proposal> = orDecoder(
  flatMapDecoder(decodeDefaultProposalType, (proposalType): Decoder<Proposal> => {
    switch (proposalType) {
      case "add":
        return decodeProposalAdd
      case "update":
        return decodeProposalUpdate
      case "remove":
        return decodeProposalRemove
      case "psk":
        return decodeProposalPSK
      case "reinit":
        return decodeProposalReinit
      case "external_init":
        return decodeProposalExternalInit
      case "group_context_extensions":
        return decodeProposalGroupContextExtensions
    }
  }),
  flatMapDecoder(decodeUint16, (n) => decodeProposalCustom(n)),
)
