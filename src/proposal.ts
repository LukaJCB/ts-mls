import { decodeUint16, decodeUint32, uint16Encoder, uint32Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, orDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CiphersuiteName, ciphersuiteEncoder, decodeCiphersuite } from "./crypto/ciphersuite.js"
import { decodeExtension, extensionEncoder, Extension } from "./extension.js"
import { decodeKeyPackage, keyPackageEncoder, KeyPackage } from "./keyPackage.js"
import { decodePskId, pskIdEncoder, PreSharedKeyID } from "./presharedkey.js"
import { decodeDefaultProposalType, defaultProposalTypeEncoder } from "./defaultProposalType.js"
import { decodeProtocolVersion, protocolVersionEncoder, ProtocolVersionName } from "./protocolVersion.js"
import { decodeLeafNodeUpdate, leafNodeEncoder, LeafNodeUpdate } from "./leafNode.js"

export interface Add {
  keyPackage: KeyPackage
}

export const addEncoder: BufferEncoder<Add> = contramapBufferEncoder(keyPackageEncoder, (a) => a.keyPackage)

export const encodeAdd: Encoder<Add> = encode(addEncoder)
export const decodeAdd: Decoder<Add> = mapDecoder(decodeKeyPackage, (keyPackage) => ({ keyPackage }))

export interface Update {
  leafNode: LeafNodeUpdate
}

export const updateEncoder: BufferEncoder<Update> = contramapBufferEncoder(leafNodeEncoder, (u) => u.leafNode)

export const encodeUpdate: Encoder<Update> = encode(updateEncoder)
export const decodeUpdate: Decoder<Update> = mapDecoder(decodeLeafNodeUpdate, (leafNode) => ({ leafNode }))

export interface Remove {
  removed: number
}

export const removeEncoder: BufferEncoder<Remove> = contramapBufferEncoder(uint32Encoder, (r) => r.removed)

export const encodeRemove: Encoder<Remove> = encode(removeEncoder)
export const decodeRemove: Decoder<Remove> = mapDecoder(decodeUint32, (removed) => ({ removed }))

export interface PSK {
  preSharedKeyId: PreSharedKeyID
}

export const pskEncoder: BufferEncoder<PSK> = contramapBufferEncoder(pskIdEncoder, (p) => p.preSharedKeyId)

export const encodePSK: Encoder<PSK> = encode(pskEncoder)
export const decodePSK: Decoder<PSK> = mapDecoder(decodePskId, (preSharedKeyId) => ({ preSharedKeyId }))

export interface Reinit {
  groupId: Uint8Array
  version: ProtocolVersionName
  cipherSuite: CiphersuiteName
  extensions: Extension[]
}

export const reinitEncoder: BufferEncoder<Reinit> = contramapBufferEncoders(
  [varLenDataEncoder, protocolVersionEncoder, ciphersuiteEncoder, varLenTypeEncoder(extensionEncoder)],
  (r) => [r.groupId, r.version, r.cipherSuite, r.extensions] as const,
)

export const encodeReinit: Encoder<Reinit> = encode(reinitEncoder)

export const decodeReinit: Decoder<Reinit> = mapDecoders(
  [decodeVarLenData, decodeProtocolVersion, decodeCiphersuite, decodeVarLenType(decodeExtension)],
  (groupId, version, cipherSuite, extensions) => ({ groupId, version, cipherSuite, extensions }),
)

export interface ExternalInit {
  kemOutput: Uint8Array
}

export const externalInitEncoder: BufferEncoder<ExternalInit> = contramapBufferEncoder(
  varLenDataEncoder,
  (e) => e.kemOutput,
)

export const encodeExternalInit: Encoder<ExternalInit> = encode(externalInitEncoder)
export const decodeExternalInit: Decoder<ExternalInit> = mapDecoder(decodeVarLenData, (kemOutput) => ({ kemOutput }))

export interface GroupContextExtensions {
  extensions: Extension[]
}

export const groupContextExtensionsEncoder: BufferEncoder<GroupContextExtensions> = contramapBufferEncoder(
  varLenTypeEncoder(extensionEncoder),
  (g) => g.extensions,
)

export const encodeGroupContextExtensions: Encoder<GroupContextExtensions> = encode(groupContextExtensionsEncoder)

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

export const proposalAddEncoder: BufferEncoder<ProposalAdd> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, addEncoder],
  (p) => [p.proposalType, p.add] as const,
)

export const encodeProposalAdd: Encoder<ProposalAdd> = encode(proposalAddEncoder)

export const proposalUpdateEncoder: BufferEncoder<ProposalUpdate> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, updateEncoder],
  (p) => [p.proposalType, p.update] as const,
)

export const encodeProposalUpdate: Encoder<ProposalUpdate> = encode(proposalUpdateEncoder)

export const proposalRemoveEncoder: BufferEncoder<ProposalRemove> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, removeEncoder],
  (p) => [p.proposalType, p.remove] as const,
)

export const encodeProposalRemove: Encoder<ProposalRemove> = encode(proposalRemoveEncoder)

export const proposalPSKEncoder: BufferEncoder<ProposalPSK> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, pskEncoder],
  (p) => [p.proposalType, p.psk] as const,
)

export const encodeProposalPSK: Encoder<ProposalPSK> = encode(proposalPSKEncoder)

export const proposalReinitEncoder: BufferEncoder<ProposalReinit> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, reinitEncoder],
  (p) => [p.proposalType, p.reinit] as const,
)

export const encodeProposalReinit: Encoder<ProposalReinit> = encode(proposalReinitEncoder)

export const proposalExternalInitEncoder: BufferEncoder<ProposalExternalInit> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, externalInitEncoder],
  (p) => [p.proposalType, p.externalInit] as const,
)

export const encodeProposalExternalInit: Encoder<ProposalExternalInit> = encode(proposalExternalInitEncoder)

export const proposalGroupContextExtensionsEncoder: BufferEncoder<ProposalGroupContextExtensions> =
  contramapBufferEncoders(
    [defaultProposalTypeEncoder, groupContextExtensionsEncoder],
    (p) => [p.proposalType, p.groupContextExtensions] as const,
  )

export const encodeProposalGroupContextExtensions: Encoder<ProposalGroupContextExtensions> = encode(
  proposalGroupContextExtensionsEncoder,
)

export const proposalCustomEncoder: BufferEncoder<ProposalCustom> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (p) => [p.proposalType, p.proposalData] as const,
)

export const encodeProposalCustom: Encoder<ProposalCustom> = encode(proposalCustomEncoder)

export const proposalEncoder: BufferEncoder<Proposal> = (p) => {
  switch (p.proposalType) {
    case "add":
      return proposalAddEncoder(p)
    case "update":
      return proposalUpdateEncoder(p)
    case "remove":
      return proposalRemoveEncoder(p)
    case "psk":
      return proposalPSKEncoder(p)
    case "reinit":
      return proposalReinitEncoder(p)
    case "external_init":
      return proposalExternalInitEncoder(p)
    case "group_context_extensions":
      return proposalGroupContextExtensionsEncoder(p)
    default:
      return proposalCustomEncoder(p)
  }
}

export const encodeProposal: Encoder<Proposal> = encode(proposalEncoder)

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
