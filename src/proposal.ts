import { decodeUint32, encodeUint32 } from "./codec/number"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite"
import { decodeExtension, encodeExtension, Extension } from "./extension"
import { decodeKeyPackage, encodeKeyPackage, KeyPackage } from "./keyPackage"
import { decodePskId, encodePskId, PreSharedKeyID } from "./presharedkey"
import { decodeProposalType, encodeProposalType } from "./proposalType"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion"
import { decodeLeafNode, encodeLeafNode, LeafNode } from "./leafNode"

export type Add = { keyPackage: KeyPackage }

export const encodeAdd: Encoder<Add> = contramapEncoder(encodeKeyPackage, (a) => a.keyPackage)
export const decodeAdd: Decoder<Add> = mapDecoder(decodeKeyPackage, (keyPackage) => ({ keyPackage }))

export type Update = { leafNode: LeafNode }

export const encodeUpdate: Encoder<Update> = contramapEncoder(encodeLeafNode, (u) => u.leafNode)
export const decodeUpdate: Decoder<Update> = mapDecoder(decodeLeafNode, (leafNode) => ({ leafNode }))

export type Remove = { removed: number }

export const encodeRemove: Encoder<Remove> = contramapEncoder(encodeUint32, (r) => r.removed)
export const decodeRemove: Decoder<Remove> = mapDecoder(decodeUint32, (removed) => ({ removed }))

export type PSK = { preSharedKeyId: PreSharedKeyID }

export const encodePSK: Encoder<PSK> = contramapEncoder(encodePskId, (p) => p.preSharedKeyId)
export const decodePSK: Decoder<PSK> = mapDecoder(decodePskId, (preSharedKeyId) => ({ preSharedKeyId }))

export type Reinit = {
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

export type ExternalInit = { kemOutput: Uint8Array }

export const encodeExternalInit: Encoder<ExternalInit> = contramapEncoder(encodeVarLenData, (e) => e.kemOutput)
export const decodeExternalInit: Decoder<ExternalInit> = mapDecoder(decodeVarLenData, (kemOutput) => ({ kemOutput }))

export type GroupContextExtensions = {
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

export type ProposalAdd = { proposalType: "add"; add: Add }

export type ProposalUpdate = { proposalType: "update"; update: Update }

export type ProposalRemove = { proposalType: "remove"; remove: Remove }

export type ProposalPSK = { proposalType: "psk"; psk: PSK }

export type ProposalReinit = {
  proposalType: "reinit"
  reinit: Reinit
}

export type ProposalExternalInit = { proposalType: "external_init"; externalInit: ExternalInit }

export type ProposalGroupContextExtensions = {
  proposalType: "group_context_extensions"
  groupContextExtensions: GroupContextExtensions
}

export type Proposal =
  | ProposalAdd
  | ProposalUpdate
  | ProposalRemove
  | ProposalPSK
  | ProposalReinit
  | ProposalExternalInit
  | ProposalGroupContextExtensions

export const encodeProposalAdd: Encoder<ProposalAdd> = contramapEncoders(
  [encodeProposalType, encodeAdd],
  (p) => [p.proposalType, p.add] as const,
)

export const encodeProposalUpdate: Encoder<ProposalUpdate> = contramapEncoders(
  [encodeProposalType, encodeUpdate],
  (p) => [p.proposalType, p.update] as const,
)

export const encodeProposalRemove: Encoder<ProposalRemove> = contramapEncoders(
  [encodeProposalType, encodeRemove],
  (p) => [p.proposalType, p.remove] as const,
)

export const encodeProposalPSK: Encoder<ProposalPSK> = contramapEncoders(
  [encodeProposalType, encodePSK],
  (p) => [p.proposalType, p.psk] as const,
)

export const encodeProposalReinit: Encoder<ProposalReinit> = contramapEncoders(
  [encodeProposalType, encodeReinit],
  (p) => [p.proposalType, p.reinit] as const,
)

export const encodeProposalExternalInit: Encoder<ProposalExternalInit> = contramapEncoders(
  [encodeProposalType, encodeExternalInit],
  (p) => [p.proposalType, p.externalInit] as const,
)

export const encodeProposalGroupContextExtensions: Encoder<ProposalGroupContextExtensions> = contramapEncoders(
  [encodeProposalType, encodeGroupContextExtensions],
  (p) => [p.proposalType, p.groupContextExtensions] as const,
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

export const decodeProposal: Decoder<Proposal> = flatMapDecoder(
  decodeProposalType,
  (proposalType): Decoder<Proposal> => {
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
      default:
        throw new Error("Unknown proposal type")
    }
  },
)

// export const decodeProposalAdd: Decoder<ProposalAdd> = mapDecoder(
//   decodeKeyPackage,
//   (keyPackage) => ({ proposalType: "add", keyPackage })
// )

// // Decoder for ProposalUpdate
// export const decodeProposalUpdate: Decoder<ProposalUpdate> = mapDecoder(
//   decodeLeafNode,
//   (leafNode) => ({ proposalType: "update", leafNode })
// )

// // Decoder for ProposalRemove
// export const decodeProposalRemove: Decoder<ProposalRemove> = mapDecoder(
//   decodeUint32,
//   (removed) => ({ proposalType: "remove", removed })
// )

// // Decoder for ProposalPSK
// export const decodeProposalPSK: Decoder<ProposalPSK> = mapDecoder(
//   decodePskId,
//   (preSharedKeyId) => ({ proposalType: "psk", preSharedKeyId })
// )

// // Decoder for ProposalReinit
// export const decodeProposalReinit: Decoder<ProposalReinit> = mapDecoders(
//   [decodeVarLenData, decodeProtocolVersion, decodeCiphersuiteName, decodeVarLenType(decodeExtension)],
//   (groupId, version, cipherSuite, extensions) => ({
//     proposalType: "reinit",
//     groupId,
//     version,
//     cipherSuite,
//     extensions,
//   })
// )

// // Decoder for ProposalExternalInit
// export const decodeProposalExternalInit: Decoder<ProposalExternalInit> = mapDecoder(
//   decodeVarLenData,
//   (kemOutput) => ({ proposalType: "external_init", kemOutput })
// )

// // Decoder for ProposalGroupContextExtensions
// export const decodeProposalGroupContextExtensions: Decoder<ProposalGroupContextExtensions> = mapDecoder(
//   decodeVarLenType(decodeExtension),
//   (extensions) => ({ proposalType: "group_context_extensions", extensions })
// )
