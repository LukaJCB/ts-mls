import { uint16Decoder, uint32Decoder, uint16Encoder, uint32Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, orDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, contramapBufferEncoders, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenTypeDecoder, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CiphersuiteId, ciphersuiteEncoder, ciphersuiteDecoder } from "./crypto/ciphersuite.js"
import { extensionEncoder, GroupContextExtension, groupContextExtensionDecoder } from "./extension.js"
import { keyPackageDecoder, keyPackageEncoder, KeyPackage } from "./keyPackage.js"
import { pskIdDecoder, pskIdEncoder, PskId } from "./presharedkey.js"
import {
  decodeDefaultProposalTypeValue,
  defaultProposalTypeValueEncoder,
  defaultProposalTypes,
  isDefaultProposalTypeValue,
} from "./defaultProposalType.js"
import { protocolVersionDecoder, protocolVersionEncoder, ProtocolVersionValue } from "./protocolVersion.js"
import { leafNodeUpdateDecoder, leafNodeEncoder, LeafNodeUpdate } from "./leafNode.js"

/** @public */
export interface Add {
  keyPackage: KeyPackage
}

export const addEncoder: Encoder<Add> = contramapBufferEncoder(keyPackageEncoder, (a) => a.keyPackage)
export const addDecoder: Decoder<Add> = mapDecoder(keyPackageDecoder, (keyPackage) => ({ keyPackage }))

/** @public */
export interface Update {
  leafNode: LeafNodeUpdate
}

export const updateEncoder: Encoder<Update> = contramapBufferEncoder(leafNodeEncoder, (u) => u.leafNode)
export const updateDecoder: Decoder<Update> = mapDecoder(leafNodeUpdateDecoder, (leafNode) => ({ leafNode }))

/** @public */
export interface Remove {
  removed: number
}

export const removeEncoder: Encoder<Remove> = contramapBufferEncoder(uint32Encoder, (r) => r.removed)
export const removeDecoder: Decoder<Remove> = mapDecoder(uint32Decoder, (removed) => ({ removed }))

/** @public */
export interface PSK {
  preSharedKeyId: PskId
}

export const pskEncoder: Encoder<PSK> = contramapBufferEncoder(pskIdEncoder, (p) => p.preSharedKeyId)
export const pSKDecoder: Decoder<PSK> = mapDecoder(pskIdDecoder, (preSharedKeyId) => ({ preSharedKeyId }))

/** @public */
export interface Reinit {
  groupId: Uint8Array
  version: ProtocolVersionValue
  cipherSuite: CiphersuiteId
  extensions: GroupContextExtension[]
}

export const reinitEncoder: Encoder<Reinit> = contramapBufferEncoders(
  [varLenDataEncoder, protocolVersionEncoder, ciphersuiteEncoder, varLenTypeEncoder(extensionEncoder)],
  (r) => [r.groupId, r.version, r.cipherSuite, r.extensions] as const,
)

export const reinitDecoder: Decoder<Reinit> = mapDecoders(
  [varLenDataDecoder, protocolVersionDecoder, ciphersuiteDecoder, varLenTypeDecoder(groupContextExtensionDecoder)],
  (groupId, version, cipherSuite, extensions) => ({ groupId, version, cipherSuite, extensions }),
)

/** @public */
export interface ExternalInit {
  kemOutput: Uint8Array
}

export const externalInitEncoder: Encoder<ExternalInit> = contramapBufferEncoder(varLenDataEncoder, (e) => e.kemOutput)
export const externalInitDecoder: Decoder<ExternalInit> = mapDecoder(varLenDataDecoder, (kemOutput) => ({ kemOutput }))

/** @public */
export interface GroupContextExtensions {
  extensions: GroupContextExtension[]
}

export const groupContextExtensionsEncoder: Encoder<GroupContextExtensions> = contramapBufferEncoder(
  varLenTypeEncoder(extensionEncoder),
  (g) => g.extensions,
)

export const groupContextExtensionsDecoder: Decoder<GroupContextExtensions> = mapDecoder(
  varLenTypeDecoder(groupContextExtensionDecoder),
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

export const proposalAddEncoder: Encoder<ProposalAdd> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, addEncoder],
  (p) => [p.proposalType, p.add] as const,
)

export const proposalUpdateEncoder: Encoder<ProposalUpdate> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, updateEncoder],
  (p) => [p.proposalType, p.update] as const,
)

export const proposalRemoveEncoder: Encoder<ProposalRemove> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, removeEncoder],
  (p) => [p.proposalType, p.remove] as const,
)

export const proposalPSKEncoder: Encoder<ProposalPSK> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, pskEncoder],
  (p) => [p.proposalType, p.psk] as const,
)

export const proposalReinitEncoder: Encoder<ProposalReinit> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, reinitEncoder],
  (p) => [p.proposalType, p.reinit] as const,
)

export const proposalExternalInitEncoder: Encoder<ProposalExternalInit> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, externalInitEncoder],
  (p) => [p.proposalType, p.externalInit] as const,
)

export const proposalGroupContextExtensionsEncoder: Encoder<ProposalGroupContextExtensions> = contramapBufferEncoders(
  [defaultProposalTypeValueEncoder, groupContextExtensionsEncoder],
  (p) => [p.proposalType, p.groupContextExtensions] as const,
)

export const proposalCustomEncoder: Encoder<ProposalCustom> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (p) => [p.proposalType, p.proposalData] as const,
)

export const proposalEncoder: Encoder<Proposal> = (p) => {
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

export const proposalAddDecoder: Decoder<ProposalAdd> = mapDecoder(addDecoder, (add) => ({
  proposalType: defaultProposalTypes.add,
  add,
}))

export const proposalUpdateDecoder: Decoder<ProposalUpdate> = mapDecoder(updateDecoder, (update) => ({
  proposalType: defaultProposalTypes.update,
  update,
}))

export const proposalRemoveDecoder: Decoder<ProposalRemove> = mapDecoder(removeDecoder, (remove) => ({
  proposalType: defaultProposalTypes.remove,
  remove,
}))

export const proposalPSKDecoder: Decoder<ProposalPSK> = mapDecoder(pSKDecoder, (psk) => ({
  proposalType: defaultProposalTypes.psk,
  psk,
}))

export const proposalReinitDecoder: Decoder<ProposalReinit> = mapDecoder(reinitDecoder, (reinit) => ({
  proposalType: defaultProposalTypes.reinit,
  reinit,
}))

export const proposalExternalInitDecoder: Decoder<ProposalExternalInit> = mapDecoder(
  externalInitDecoder,
  (externalInit) => ({ proposalType: defaultProposalTypes.external_init, externalInit }),
)

export const proposalGroupContextExtensionsDecoder: Decoder<ProposalGroupContextExtensions> = mapDecoder(
  groupContextExtensionsDecoder,
  (groupContextExtensions) => ({
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions,
  }),
)

export function proposalCustomDecoder(proposalType: number): Decoder<ProposalCustom> {
  return mapDecoder(varLenDataDecoder, (proposalData) => ({ proposalType, proposalData }))
}

export const proposalDecoder: Decoder<Proposal> = orDecoder(
  flatMapDecoder(decodeDefaultProposalTypeValue, (proposalType): Decoder<Proposal> => {
    switch (proposalType) {
      case defaultProposalTypes.add:
        return proposalAddDecoder
      case defaultProposalTypes.update:
        return proposalUpdateDecoder
      case defaultProposalTypes.remove:
        return proposalRemoveDecoder
      case defaultProposalTypes.psk:
        return proposalPSKDecoder
      case defaultProposalTypes.reinit:
        return proposalReinitDecoder
      case defaultProposalTypes.external_init:
        return proposalExternalInitDecoder
      case defaultProposalTypes.group_context_extensions:
        return proposalGroupContextExtensionsDecoder
    }
  }),
  flatMapDecoder(uint16Decoder, (n) => proposalCustomDecoder(n)),
)
