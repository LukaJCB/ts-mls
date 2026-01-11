import { decodeUint16, decodeUint32, uint16Encoder, uint32Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, orDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CiphersuiteId, ciphersuiteEncoder, decodeCiphersuite } from "./crypto/ciphersuite.js"
import { decodeExtension, extensionEncoder, Extension } from "./extension.js"
import { decodeKeyPackage, keyPackageEncoder, KeyPackage } from "./keyPackage.js"
import { decodePskId, pskIdEncoder, PreSharedKeyID } from "./presharedkey.js"
import {
  decodeDefaultProposalTypeValue,
  defaultProposalTypeValueEncoder,
  defaultProposalTypes,
  isDefaultProposalTypeValue,
} from "./defaultProposalType.js"
import { decodeProtocolVersion, protocolVersionEncoder, ProtocolVersionValue } from "./protocolVersion.js"
import { decodeLeafNodeUpdate, leafNodeEncoder, LeafNodeUpdate } from "./leafNode.js"

/** @public */
export interface Add {
  keyPackage: KeyPackage
}

export const addEncoder: BufferEncoder<Add> = contramapBufferEncoder(keyPackageEncoder, (a) => a.keyPackage)

export const encodeAdd: Encoder<Add> = encode(addEncoder)
export const decodeAdd: Decoder<Add> = mapDecoder(decodeKeyPackage, (keyPackage) => ({ keyPackage }))

/** @public */
export interface Update {
  leafNode: LeafNodeUpdate
}

export const updateEncoder: BufferEncoder<Update> = contramapBufferEncoder(leafNodeEncoder, (u) => u.leafNode)

export const encodeUpdate: Encoder<Update> = encode(updateEncoder)
export const decodeUpdate: Decoder<Update> = mapDecoder(decodeLeafNodeUpdate, (leafNode) => ({ leafNode }))

/** @public */
export interface Remove {
  removed: number
}

export const removeEncoder: BufferEncoder<Remove> = contramapBufferEncoder(uint32Encoder, (r) => r.removed)

export const encodeRemove: Encoder<Remove> = encode(removeEncoder)
export const decodeRemove: Decoder<Remove> = mapDecoder(decodeUint32, (removed) => ({ removed }))

/** @public */
export interface PSK {
  preSharedKeyId: PreSharedKeyID
}

export const pskEncoder: BufferEncoder<PSK> = contramapBufferEncoder(pskIdEncoder, (p) => p.preSharedKeyId)

export const encodePSK: Encoder<PSK> = encode(pskEncoder)
export const decodePSK: Decoder<PSK> = mapDecoder(decodePskId, (preSharedKeyId) => ({ preSharedKeyId }))

/** @public */
export interface Reinit {
  groupId: Uint8Array
  version: ProtocolVersionValue
  cipherSuite: CiphersuiteId
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

/** @public */
export interface ExternalInit {
  kemOutput: Uint8Array
}

export const externalInitEncoder: BufferEncoder<ExternalInit> = contramapBufferEncoder(
  varLenDataEncoder,
  (e) => e.kemOutput,
)

export const encodeExternalInit: Encoder<ExternalInit> = encode(externalInitEncoder)
export const decodeExternalInit: Decoder<ExternalInit> = mapDecoder(decodeVarLenData, (kemOutput) => ({ kemOutput }))

/** @public */
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

/** @public */
export interface ProposalAdd {
  proposalType: typeof defaultProposalTypes.add
  add: Add
}

/** @public */
export interface ProposalUpdate {
  proposalType: typeof defaultProposalTypes.update
  update: Update
}

/** @public */
export interface ProposalRemove {
  proposalType: typeof defaultProposalTypes.remove
  remove: Remove
}

/** @public */
export interface ProposalPSK {
  proposalType: typeof defaultProposalTypes.psk
  psk: PSK
}

/** @public */
export interface ProposalReinit {
  proposalType: typeof defaultProposalTypes.reinit
  reinit: Reinit
}

/** @public */
export interface ProposalExternalInit {
  proposalType: typeof defaultProposalTypes.external_init
  externalInit: ExternalInit
}

/** @public */
export interface ProposalGroupContextExtensions {
  proposalType: typeof defaultProposalTypes.group_context_extensions
  groupContextExtensions: GroupContextExtensions
}

/** @public */
export interface ProposalCustom {
  proposalType: number
  proposalData: Uint8Array
}

/** @public */
export type DefaultProposal =
  | ProposalAdd
  | ProposalUpdate
  | ProposalRemove
  | ProposalPSK
  | ProposalReinit
  | ProposalExternalInit
  | ProposalGroupContextExtensions

/** @public */
export type Proposal = DefaultProposal | ProposalCustom

export function isDefaultProposal(p: Proposal): p is DefaultProposal {
  return isDefaultProposalTypeValue(p.proposalType)
}

export const proposalAddEncoder: BufferEncoder<ProposalAdd> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, addEncoder],
  (p) => [p.proposalType, p.add] as const,
)

export const encodeProposalAdd: Encoder<ProposalAdd> = encode(proposalAddEncoder)

export const proposalUpdateEncoder: BufferEncoder<ProposalUpdate> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, updateEncoder],
  (p) => [p.proposalType, p.update] as const,
)

export const encodeProposalUpdate: Encoder<ProposalUpdate> = encode(proposalUpdateEncoder)

export const proposalRemoveEncoder: BufferEncoder<ProposalRemove> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, removeEncoder],
  (p) => [p.proposalType, p.remove] as const,
)

export const encodeProposalRemove: Encoder<ProposalRemove> = encode(proposalRemoveEncoder)

export const proposalPSKEncoder: BufferEncoder<ProposalPSK> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, pskEncoder],
  (p) => [p.proposalType, p.psk] as const,
)

export const encodeProposalPSK: Encoder<ProposalPSK> = encode(proposalPSKEncoder)

export const proposalReinitEncoder: BufferEncoder<ProposalReinit> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, reinitEncoder],
  (p) => [p.proposalType, p.reinit] as const,
)

export const encodeProposalReinit: Encoder<ProposalReinit> = encode(proposalReinitEncoder)

export const proposalExternalInitEncoder: BufferEncoder<ProposalExternalInit> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, externalInitEncoder],
  (p) => [p.proposalType, p.externalInit] as const,
)

export const encodeProposalExternalInit: Encoder<ProposalExternalInit> = encode(proposalExternalInitEncoder)

export const proposalGroupContextExtensionsEncoder: BufferEncoder<ProposalGroupContextExtensions> =
  contramapBufferEncoders(
    [defaultProposalTypeValueEncoder, groupContextExtensionsEncoder],
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
  if (!isDefaultProposal(p)) return proposalCustomEncoder(p)

  switch (p.proposalType) {
    case defaultProposalTypes.add:
      return proposalAddEncoder(p)
    case defaultProposalTypes.update:
      return proposalUpdateEncoder(p)
    case defaultProposalTypes.remove:
      return proposalRemoveEncoder(p)
    case defaultProposalTypes.psk:
      return proposalPSKEncoder(p)
    case defaultProposalTypes.reinit:
      return proposalReinitEncoder(p)
    case defaultProposalTypes.external_init:
      return proposalExternalInitEncoder(p)
    case defaultProposalTypes.group_context_extensions:
      return proposalGroupContextExtensionsEncoder(p)
  }
}

export const encodeProposal: Encoder<Proposal> = encode(proposalEncoder)

export const decodeProposalAdd: Decoder<ProposalAdd> = mapDecoder(decodeAdd, (add) => ({
  proposalType: defaultProposalTypes.add,
  add,
}))

export const decodeProposalUpdate: Decoder<ProposalUpdate> = mapDecoder(decodeUpdate, (update) => ({
  proposalType: defaultProposalTypes.update,
  update,
}))

export const decodeProposalRemove: Decoder<ProposalRemove> = mapDecoder(decodeRemove, (remove) => ({
  proposalType: defaultProposalTypes.remove,
  remove,
}))

export const decodeProposalPSK: Decoder<ProposalPSK> = mapDecoder(decodePSK, (psk) => ({
  proposalType: defaultProposalTypes.psk,
  psk,
}))

export const decodeProposalReinit: Decoder<ProposalReinit> = mapDecoder(decodeReinit, (reinit) => ({
  proposalType: defaultProposalTypes.reinit,
  reinit,
}))

export const decodeProposalExternalInit: Decoder<ProposalExternalInit> = mapDecoder(
  decodeExternalInit,
  (externalInit) => ({ proposalType: defaultProposalTypes.external_init, externalInit }),
)

export const decodeProposalGroupContextExtensions: Decoder<ProposalGroupContextExtensions> = mapDecoder(
  decodeGroupContextExtensions,
  (groupContextExtensions) => ({
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions,
  }),
)

export function decodeProposalCustom(proposalType: number): Decoder<ProposalCustom> {
  return mapDecoder(decodeVarLenData, (proposalData) => ({ proposalType, proposalData }))
}

export const decodeProposal: Decoder<Proposal> = orDecoder(
  flatMapDecoder(decodeDefaultProposalTypeValue, (proposalType): Decoder<Proposal> => {
    switch (proposalType) {
      case defaultProposalTypes.add:
        return decodeProposalAdd
      case defaultProposalTypes.update:
        return decodeProposalUpdate
      case defaultProposalTypes.remove:
        return decodeProposalRemove
      case defaultProposalTypes.psk:
        return decodeProposalPSK
      case defaultProposalTypes.reinit:
        return decodeProposalReinit
      case defaultProposalTypes.external_init:
        return decodeProposalExternalInit
      case defaultProposalTypes.group_context_extensions:
        return decodeProposalGroupContextExtensions
    }
  }),
  flatMapDecoder(decodeUint16, (n) => decodeProposalCustom(n)),
)
