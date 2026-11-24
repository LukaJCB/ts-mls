import { AuthenticatedContent, makeProposalRef } from "./authenticatedContent.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Hash } from "./crypto/hash.js"
import {
  extensionsEqual,
  extensionsSupportedByCapabilities,
  findExtension,
  GroupContextExtension,
  GroupInfoExtension,
  isExternalSendersExtension,
  isRequiredCapabilitiesExtension,
} from "./extension.js"
import { createConfirmationTag, FramedContentCommit } from "./framedContent.js"
import { groupContextDecoder, GroupContext, groupContextEncoder } from "./groupContext.js"
import { ratchetTreeFromExtension, verifyGroupInfoConfirmationTag, verifyGroupInfoSignature } from "./groupInfo.js"
import { KeyPackage, makeKeyPackageRef, PrivateKeyPackage } from "./keyPackage.js"
import {
  keyScheduleDecoder,
  deriveKeySchedule,
  initializeKeySchedule,
  KeySchedule,
  keyScheduleEncoder,
} from "./keySchedule.js"
import { PskId, pskIdEncoder, pskTypes, resumptionPSKUsages } from "./presharedkey.js"

import {
  ratchetTreeDecoder,
  findBlankLeafNodeIndexOrExtend,
  findLeafIndex,
  ratchetTreeEncoder,
  addLeafNodeMutable,
  removeLeafNodeMutable,
  updateLeafNodeMutable,
} from "./ratchetTree.js"
import { RatchetTree } from "./ratchetTree.js"
import {
  appendSecretTreeValues,
  createSecretTree,
  SecretTree,
  secretTreeDecoder,
  secretTreeEncoder,
} from "./secretTree.js"
import { createConfirmedHash, createInterimHash } from "./transcriptHash.js"
import { treeHashRoot, TreeHashCache } from "./treeHash.js"
import { LeafIndex, leafToNodeIndex, leafWidth, nodeToLeafIndex, toLeafIndex } from "./treemath.js"
import { WireformatName, wireformats } from "./wireformat.js"
import { ProposalOrRef, proposalOrRefTypes } from "./proposalOrRefType.js"
import {
  ExternalInit,
  GroupContextExtensions,
  isDefaultProposal,
  Proposal,
  ProposalAdd,
  ProposalGroupContextExtensions,
  ProposalUpdate,
  PSK,
  Reinit,
} from "./proposal.js"
import { defaultProposalTypes } from "./defaultProposalType.js"
import { pathToRoot } from "./pathSecrets.js"
import {
  PrivateKeyPath,
  privateKeyPathDecoder,
  mergePrivateKeyPaths,
  privateKeyPathEncoder,
  toPrivateKeyPath,
} from "./privateKeyPath.js"
import {
  UnappliedProposals,
  addUnappliedProposal,
  ProposalWithSender,
  unappliedProposalsEncoder,
  unappliedProposalsDecoder,
} from "./unappliedProposals.js"
import { accumulatePskSecret, PskIndex } from "./pskIndex.js"
import { getSenderLeafNodeIndex } from "./sender.js"
import { addToMap } from "./util/addToMap.js"
import { bytesToBase64, zeroOutUint8Array } from "./util/byteArray.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"
import {
  CryptoVerificationError,
  CodecError,
  InternalError,
  UsageError,
  ValidationError,
  AuthenticationError,
} from "./mlsError.js"

import { LeafNode } from "./leafNode.js"
import { nodeTypes } from "./nodeType.js"
import { protocolVersions } from "./protocolVersion.js"
import { firstCommonAncestor, UpdatePath } from "./updatePath.js"
import { decryptGroupInfo, decryptGroupSecrets, Welcome } from "./welcome.js"
import { AuthenticationService } from "./authenticationService.js"
import { ClientConfig, defaultClientConfig } from "./clientConfig.js"
import { Encoder, contramapBufferEncoders, encode } from "./codec/tlsEncoder.js"

import {
  bigintMapEncoder,
  bigintMapDecoder,
  varLenDataDecoder,
  varLenDataEncoder,
  varLenTypeDecoder,
  varLenTypeEncoder,
} from "./codec/variableLength.js"
import { optionalDecoder, optionalEncoder } from "./codec/optional.js"
import { groupActiveStateDecoder, GroupActiveState, groupActiveStateEncoder } from "./groupActiveState.js"
import { epochReceiverDataDecoder, EpochReceiverData, epochReceiverDataEncoder } from "./epochReceiverData.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { deriveSecret } from "./crypto/kdf.js"
import { MlsContext } from "./mlsContext.js"
import { throwIfDefined, validateReinit, validateRatchetTree, validateExternalSenders } from "./validation.js"
import { SignatureKeyPair } from "./signatureKeyPair.js"
import { RequiredCapabilities } from "./requiredCapabilities.js"
import { defaultExtensionTypes } from "./defaultExtensionType.js"
import {
  validateProposalsExtractAuthIndices,
  authenticateCredentials,
  validateProposalsAgainstFullTree,
  LeafValidationInput,
  ParsedGroupContextExtensions,
} from "./validationTreeContext.js"
import { ExternalSender } from "./externalSender.js"
import { LeafChange } from "./leafChange.js"

/** @public */
export type ClientState = GroupState & PublicGroupState

/** @public */
export interface PublicGroupState {
  ratchetTree: RatchetTree
  groupContext: GroupContext
}

/** @public */
export interface GroupState {
  keySchedule: KeySchedule
  secretTree: SecretTree
  privatePath: PrivateKeyPath
  signaturePrivateKey: Uint8Array
  unappliedProposals: UnappliedProposals
  confirmationTag: Uint8Array
  historicalReceiverData: Map<bigint, EpochReceiverData>
  groupActiveState: GroupActiveState
  treeHashCache: TreeHashCache
}

/** @public */
export const publicGroupStateEncoder: Encoder<PublicGroupState> = contramapBufferEncoders(
  [groupContextEncoder, ratchetTreeEncoder],
  (state) => [state.groupContext, state.ratchetTree] as const,
)

const treeHashCacheEncoder: Encoder<TreeHashCache> = varLenTypeEncoder(optionalEncoder(varLenDataEncoder))
const treeHashCacheDecoder: Decoder<TreeHashCache> = varLenTypeDecoder(optionalDecoder(varLenDataDecoder))

/** @public */
export const groupStateEncoder: Encoder<GroupState> = contramapBufferEncoders(
  [
    keyScheduleEncoder,
    secretTreeEncoder,
    privateKeyPathEncoder,
    varLenDataEncoder,
    unappliedProposalsEncoder,
    varLenDataEncoder,
    bigintMapEncoder(epochReceiverDataEncoder),
    groupActiveStateEncoder,
    treeHashCacheEncoder,
  ],
  (state) =>
    [
      state.keySchedule,
      state.secretTree,
      state.privatePath,
      state.signaturePrivateKey,
      state.unappliedProposals,
      state.confirmationTag,
      state.historicalReceiverData,
      state.groupActiveState,
      state.treeHashCache,
    ] as const,
)

/** @public */
export const clientStateEncoder: Encoder<ClientState> = contramapBufferEncoders(
  [publicGroupStateEncoder, groupStateEncoder],
  (state) => [state, state] as const,
)

/** @public */
export const publicGroupStateDecoder: Decoder<PublicGroupState> = mapDecoders(
  [groupContextDecoder, ratchetTreeDecoder],
  (groupContext, ratchetTree) => ({
    groupContext,
    ratchetTree,
  }),
)

/** @public */
export const groupStateDecoder: Decoder<GroupState> = mapDecoders(
  [
    keyScheduleDecoder,
    secretTreeDecoder,
    privateKeyPathDecoder,
    varLenDataDecoder,
    unappliedProposalsDecoder,
    varLenDataDecoder,
    bigintMapDecoder(epochReceiverDataDecoder),
    groupActiveStateDecoder,
    treeHashCacheDecoder,
  ],
  (
    keySchedule,
    secretTree,
    privatePath,
    signaturePrivateKey,
    unappliedProposals,
    confirmationTag,
    historicalReceiverData,
    groupActiveState,
    treeHashCache,
  ) => ({
    keySchedule,
    secretTree,
    privatePath,
    signaturePrivateKey,
    unappliedProposals,
    confirmationTag,
    historicalReceiverData,
    groupActiveState,
    treeHashCache,
  }),
)

/** @public */
export const clientStateDecoder: Decoder<ClientState> = mapDecoders(
  [publicGroupStateDecoder, groupStateDecoder],
  (publicState, state) => ({
    ...publicState,
    ...state,
  }),
)

/** @public */
export function getOwnLeafNode(state: ClientState): LeafNode {
  const idx = leafToNodeIndex(toLeafIndex(state.privatePath.leafIndex))
  const leaf = state.ratchetTree[idx]
  if (leaf?.nodeType !== nodeTypes.leaf) throw new InternalError("Expected leaf node")
  return leaf.leaf
}

/** @public */
export function getLeafNodeAt(state: ClientState, leafIndex: number): LeafNode {
  const idx = leafToNodeIndex(toLeafIndex(leafIndex))
  const leaf = state.ratchetTree[idx]
  if (!leaf) throw new UsageError("No leaf at given leafIndex")
  if (leaf.nodeType !== nodeTypes.leaf) throw new InternalError("Expected leaf node")
  return leaf.leaf
}

/** @public */
export function getOwnSignatureKeyPair(state: ClientState): SignatureKeyPair {
  return {
    signKey: state.signaturePrivateKey,
    publicKey: getOwnLeafNode(state).signaturePublicKey,
  }
}

/** @public */
export function getGroupMembers(state: ClientState): LeafNode[] {
  return extractFromGroupMembers(
    state,
    () => false,
    (l) => l,
  )
}

export function extractFromGroupMembers<T>(
  state: ClientState,
  exclude: (l: LeafNode) => boolean,
  map: (l: LeafNode) => T,
): T[] {
  const recipients = []
  for (const node of state.ratchetTree) {
    if (node?.nodeType === nodeTypes.leaf && !exclude(node.leaf)) {
      recipients.push(map(node.leaf))
    }
  }
  return recipients
}

export function checkCanSendApplicationMessages(state: ClientState): void {
  if (Object.keys(state.unappliedProposals).length !== 0)
    throw new UsageError("Cannot send application message with unapplied proposals")

  checkCanSendHandshakeMessages(state)
}

export function checkCanSendHandshakeMessages(state: ClientState): void {
  if (state.groupActiveState.kind === "suspendedPendingReinit")
    throw new UsageError("Cannot send messages while Group is suspended pending reinit")
  else if (state.groupActiveState.kind === "removedFromGroup")
    throw new UsageError("Cannot send messages after being removed from group")
}

export interface ApplyProposalsResult {
  pskSecret: Uint8Array
  pskIds: PskId[]
  needsUpdatePath: boolean
  additionalResult: ApplyProposalsData
  selfRemoved: boolean
  allProposals: ProposalWithSender[]
  updatedLeaves: LeafIndex[]
  removedLeaves: LeafIndex[]
}

type ApplyProposalsData =
  | { kind: "memberCommit"; addedLeafNodes: [LeafIndex, KeyPackage][]; extensions: GroupContextExtension[] | undefined }
  | { kind: "externalCommit"; externalInitSecret: Uint8Array; newMemberLeafIndex: LeafIndex }
  | { kind: "reinit"; reinit: Reinit }

interface CommitProposals {
  proposal: Proposal
  senderLeafIndex: number | undefined
  authenticated: boolean
}

type PreprocessedProposals = {
  committerLeafIndex: LeafIndex
  leafValidation: LeafValidationInput
  allProposals: CommitProposals[]
} & (
  | {
      kind: "memberCommit"
      psks: PSK[]
    }
  | {
      kind: "externalInit"
      externalInit: ExternalInit
      psks: PSK[]
    }
  | {
      kind: "reinit"
      reinit: Reinit
    }
)

function preprocessProposals(
  proposals: ProposalOrRef[],
  updatePath: { path: UpdatePath; authenticated: boolean } | undefined,
  committerLeafIndex: LeafIndex | undefined,
  tree: RatchetTree,
  unappliedProposals: UnappliedProposals,
  sentByClient: boolean,
): PreprocessedProposals {
  const adds = new Array<{ keyPackage: KeyPackage; authenticated: boolean; sentByClient: boolean }>()
  const leafChanges = new Map<LeafIndex, LeafChange>()
  const removals = new Set<LeafIndex>()
  const psks = new Array<PSK>()
  const pskIds = new Set<string>()
  const allProposals = new Array<CommitProposals>()
  let gce: { groupContextExtensions: GroupContextExtensions; inline: boolean } | undefined
  let externalInit: ExternalInit | undefined
  let reinit: Reinit | undefined
  let hasReferences = false

  function handleProposal(proposal: Proposal, inline: boolean, senderLeafIndex?: number) {
    if (isDefaultProposal(proposal)) {
      switch (proposal.proposalType) {
        case defaultProposalTypes.add:
          adds.push({ keyPackage: proposal.add.keyPackage, authenticated: !inline, sentByClient }) //todo correct?
          break
        case defaultProposalTypes.update: {
          if (inline) {
            throw new ValidationError("Committer can't update themselves via proposal")
          }
          if (senderLeafIndex === undefined) throw new Error("Can't apply update proposal from unknown sender? TODO")
          const leafIndex = toLeafIndex(senderLeafIndex)
          const existing = tree[leafToNodeIndex(leafIndex)]
          if (existing?.nodeType !== nodeTypes.leaf) throw new Error("Empty leaf for update proposal")
          checkLeafTarget(leafIndex, committerLeafIndex, leafChanges, removals)
          leafChanges.set(leafIndex, {
            oldLeafNode: existing.leaf,
            newLeafNode: proposal.update.leafNode,
            authenticated: true,
          })
          break
        }
        case defaultProposalTypes.remove: {
          if (inline && proposal.remove.removed === committerLeafIndex) {
            throw new ValidationError("Commiter can't remove themselves via inline proposal")
          }
          const removedIndex = toLeafIndex(proposal.remove.removed)
          if (tree[leafToNodeIndex(removedIndex)] === undefined) {
            throw new ValidationError("Remove Proposal cannot target empty leaf")
          }

          checkLeafTarget(removedIndex, committerLeafIndex, leafChanges, removals)
          removals.add(removedIndex)
          break
        }
        case defaultProposalTypes.psk: {
          const asString = bytesToBase64(encode(pskIdEncoder, proposal.psk.preSharedKeyId))
          if (pskIds.has(asString))
            throw new ValidationError(
              "Commit cannot contain multiple PreSharedKey proposals that reference the same PreSharedKeyID",
            )
          pskIds.add(asString)
          psks.push(proposal.psk)
          break
        }
        case defaultProposalTypes.group_context_extensions: {
          if (gce !== undefined)
            throw new ValidationError("Commit cannot contain multiple GroupContextExtension Proposals")
          else gce = { groupContextExtensions: proposal.groupContextExtensions, inline }
          break
        }
        case defaultProposalTypes.reinit: {
          if (reinit !== undefined) throw new ValidationError("Commit cannot contain multiple reinit Proposals")
          reinit = proposal.reinit
          break
        }
        case defaultProposalTypes.external_init: {
          if (externalInit !== undefined)
            throw new ValidationError("Commit cannot contain multiple external_init Proposals")
          externalInit = proposal.externalInit
          break
        }
      }
    }
  }

  for (const proposal of proposals) {
    if (proposal.proposalOrRefType === proposalOrRefTypes.proposal) {
      handleProposal(proposal.proposal, true)
      allProposals.push({ proposal: proposal.proposal, senderLeafIndex: committerLeafIndex, authenticated: false })
    } else {
      const p = unappliedProposals[bytesToBase64(proposal.reference)]
      if (p === undefined) throw new ValidationError("Could not find proposal with supplied reference")
      hasReferences = true
      handleProposal(p.proposal, false, p.senderLeafIndex)
      allProposals.push({ ...p, authenticated: true })
    }
  }

  if (externalInit !== undefined) {
    if (removals.size > 1) throw new ValidationError("ExternalInit can only have up to one Remove proposal")
    if (adds.length > 0) throw new ValidationError("ExternalInit cannot have Add Proposal")
    if (leafChanges.size > 0) throw new ValidationError("ExternalInit cannot have Update Proposal")
    if (gce !== undefined) throw new ValidationError("ExternalInit cannot have GroupContextExtensions Proposal")
    if (reinit !== undefined) throw new ValidationError("ExternalInit cannot have Reinit proposal")
    if (hasReferences) throw new ValidationError("ExternalInit cannot have proposal references")
    if (committerLeafIndex !== undefined) throw new ValidationError("ExternalInit cannot come from a member commit")

    const remove = removals.values().next().value

    const availableLeafIndex = nodeToLeafIndex(findBlankLeafNodeIndexOrExtend(tree))

    const externalCommiterLeafIndex =
      remove === undefined ? availableLeafIndex : toLeafIndex(Math.min(availableLeafIndex, remove))
    if (updatePath === undefined) {
      throw new ValidationError("ExternalInit must have an UpdatePath?")
    }

    const leafChange: LeafChange = {
      newLeafNode: updatePath.path.leafNode,
      authenticated: updatePath.authenticated,
      oldLeafNode: undefined,
    }

    if (remove !== undefined) {
      const removeNodeIndex = leafToNodeIndex(remove)
      const oldLeafNode = tree[removeNodeIndex]

      if (oldLeafNode === undefined || oldLeafNode.nodeType === nodeTypes.parent) {
        throw new InternalError("Found parent node in leaf Node position")
      }

      leafChange["oldLeafNode"] = oldLeafNode.leaf
    }
    leafChanges.set(externalCommiterLeafIndex, leafChange)
    const leafValidation = {
      adds,
      leafChanges,
      removals,
      groupContextExtensions: undefined,
    }

    return {
      kind: "externalInit",
      externalInit,
      committerLeafIndex: externalCommiterLeafIndex,
      leafValidation,
      psks,
      allProposals,
    }
  }

  if (committerLeafIndex === undefined) {
    throw new ValidationError("Member commit must have a commiter leafIndex")
  }

  if (updatePath !== undefined) {
    const oldLeafNode = tree[leafToNodeIndex(committerLeafIndex)]
    if (oldLeafNode?.nodeType === nodeTypes.parent) {
      throw new InternalError("Found parent node in leaf position")
    }
    leafChanges.set(committerLeafIndex, {
      newLeafNode: updatePath.path.leafNode,
      oldLeafNode: oldLeafNode?.leaf,
      authenticated: updatePath.authenticated,
    })
  }

  if (reinit !== undefined) {
    if (proposals.length > 1) {
      throw new ValidationError("Reinit cannot contain any other proposals")
    }
    const oldLeafNode = tree[leafToNodeIndex(committerLeafIndex)]
    if (oldLeafNode?.nodeType !== nodeTypes.leaf) {
      throw new InternalError("expected leaf node")
    }

    const leafValidation: LeafValidationInput = {
      leafChanges,
      adds: [],
      removals: new Set(),
      groupContextExtensions: undefined,
    }
    return { kind: "reinit", reinit, committerLeafIndex, leafValidation, allProposals }
  }

  const groupContextExtensions = gce !== undefined ? parseGce(gce.groupContextExtensions, !gce.inline) : undefined

  const leafValidation = {
    adds,
    leafChanges,
    removals,
    groupContextExtensions,
  }

  return { kind: "memberCommit", committerLeafIndex, psks, leafValidation, allProposals }
}

function checkLeafTarget(
  leafIndex: LeafIndex,
  committerLeafIndex: LeafIndex | undefined,
  leafChanges: Map<LeafIndex, LeafChange>,
  removals: Set<LeafIndex>,
): void {
  if (leafIndex === committerLeafIndex) {
    throw new ValidationError("Commit cannot update or remove the committer via a proposal")
  }

  if (leafChanges.has(leafIndex) || removals.has(leafIndex)) {
    throw new ValidationError(
      "Commit cannot contain multiple update and/or remove proposals " + "that apply to the same leaf",
    )
  }
}

function parseGce(gce: GroupContextExtensions, authenticated: boolean): ParsedGroupContextExtensions {
  const seen = new Set<number>()
  let newExternalSenders: ExternalSender[] | undefined = undefined
  let newRequiredCapabilities: RequiredCapabilities | undefined = undefined
  for (const extension of gce.extensions) {
    if (seen.has(extension.extensionType)) {
      throw new ValidationError(`Duplicate extension type: ${extension.extensionType}`)
    }
    seen.add(extension.extensionType)

    if (isExternalSendersExtension(extension)) {
      newExternalSenders = extension.extensionData
    } else if (isRequiredCapabilitiesExtension(extension)) {
      newRequiredCapabilities = extension.extensionData
    }
  }

  return { groupContextExtensions: gce.extensions, authenticated, newExternalSenders, newRequiredCapabilities }
}

export async function applyProposals(
  state: ClientState,
  mutableTree: RatchetTree,
  updatePath: UpdatePath | undefined,
  proposals: ProposalOrRef[],
  committerLeafIndex: LeafIndex | undefined,
  pskSearch: PskIndex,
  clientConfig: ClientConfig,
  authService: AuthenticationService,
  sentByClient: boolean,
  cs: CiphersuiteImpl,
): Promise<ApplyProposalsResult> {
  const existingRequiredCapabilities = findExtension(
    defaultExtensionTypes.required_capabilities,
    state.groupContext.extensions,
  )

  const processedProposals = preprocessProposals(
    proposals,
    updatePath !== undefined ? { path: updatePath, authenticated: false } : undefined,
    committerLeafIndex,
    mutableTree,
    state.unappliedProposals,
    sentByClient,
  )

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const [updatedPskSecret, pskIds] =
    processedProposals.kind !== "reinit"
      ? await accumulatePskSecret(
          processedProposals.psks.map((p) => p.preSharedKeyId),
          pskSearch,
          cs,
          zeroes,
        )
      : [zeroes, []]

  const requiredCapabilities =
    processedProposals.leafValidation.groupContextExtensions === undefined
      ? existingRequiredCapabilities
      : processedProposals.leafValidation.groupContextExtensions.newRequiredCapabilities

  const authIndices = await validateProposalsExtractAuthIndices(
    processedProposals.leafValidation,
    updatePath?.nodes,
    requiredCapabilities,
    state.groupContext,
    processedProposals.leafValidation.groupContextExtensions?.groupContextExtensions ?? state.groupContext.extensions,
    clientConfig,
    authService.batchSize,
    cs.signature,
  )

  throwIfDefined(
    validateProposalsAgainstFullTree(
      mutableTree,
      authIndices.treeIndexes,
      processedProposals.leafValidation,
      clientConfig.keyPackageEqualityConfig,
      processedProposals.leafValidation.removals,
      processedProposals.leafValidation.groupContextExtensions,
    ),
  )

  if (authIndices.authInput.length > 0) {
    const authResult = await authenticateCredentials(authIndices.authInput, authService)
    if (authResult.kind === "error") {
      throw new AuthenticationError(authResult.error)
    }
  }

  const newExtensions = processedProposals.leafValidation.groupContextExtensions?.groupContextExtensions

  const addedLeafNodes = await applyTreeMutations(mutableTree, processedProposals)

  const selfRemoved = mutableTree[leafToNodeIndex(toLeafIndex(state.privatePath.leafIndex))] === undefined

  const needsUpdatePath =
    processedProposals.allProposals.length === 0 ||
    processedProposals.allProposals.some(({ proposal }) => {
      const t = proposal.proposalType
      return t !== defaultProposalTypes.add && t !== defaultProposalTypes.psk && t !== defaultProposalTypes.reinit
    })

  //TODO we could gather all of these in applyTreeMutations?
  const updatedLeaves: LeafIndex[] = [
    ...processedProposals.leafValidation.leafChanges.keys(),
    ...addedLeafNodes.map(([leafIndex]) => leafIndex),
  ]
  const removedLeaves: LeafIndex[] = [...processedProposals.leafValidation.removals]

  const proposalsData: ApplyProposalsData = await deriveProposalsData(
    processedProposals,
    cs,
    state,
    mutableTree,
    addedLeafNodes,
    newExtensions,
  )

  return {
    pskSecret: updatedPskSecret,
    additionalResult: proposalsData,
    pskIds,
    needsUpdatePath,
    selfRemoved,
    allProposals: processedProposals.allProposals,
    updatedLeaves,
    removedLeaves,
  }
}

async function deriveProposalsData(
  proposals: PreprocessedProposals,
  cs: CiphersuiteImpl,
  state: ClientState,
  mutableTree: RatchetTree,
  addedLeafNodes: [LeafIndex, KeyPackage][],
  newExtensions: GroupContextExtension[] | undefined,
): Promise<ApplyProposalsData> {
  if (proposals.kind === "externalInit") {
    const externalKeyPair = await cs.hpke.deriveKeyPair(state.keySchedule.externalSecret)

    const externalInitSecret = await importSecret(
      await cs.hpke.exportPrivateKey(externalKeyPair.privateKey),
      proposals.externalInit.kemOutput,
      cs,
    )

    return {
      kind: "externalCommit",
      externalInitSecret,
      newMemberLeafIndex: nodeToLeafIndex(findBlankLeafNodeIndexOrExtend(mutableTree)),
    }

    //12.4.3.2 External Commits MUST contain a path field (and is therefore a "full" Commit)
  } else if (proposals.kind === "reinit") {
    const reinit = proposals.reinit

    throwIfDefined(validateReinit(proposals.reinit, state.groupContext))

    return {
      kind: "reinit",
      reinit,
    }
  } else {
    return {
      kind: "memberCommit" as const,
      addedLeafNodes,
      extensions: newExtensions,
    }
  }
}

/** @public */
export function makePskIndex(state: ClientState | undefined, externalPsks: Record<string, Uint8Array>): PskIndex {
  return {
    findPsk(preSharedKeyId) {
      if (preSharedKeyId.psktype === pskTypes.external) {
        return externalPsks[bytesToBase64(preSharedKeyId.pskId)]
      }

      if (state !== undefined && constantTimeEqual(preSharedKeyId.pskGroupId, state.groupContext.groupId)) {
        if (preSharedKeyId.pskEpoch === state.groupContext.epoch) return state.keySchedule.resumptionPsk
        else return state.historicalReceiverData.get(preSharedKeyId.pskEpoch)?.resumptionPsk
      }
    },
  }
}

export async function nextEpochContext(
  groupContext: GroupContext,
  wireformat: WireformatName,
  content: FramedContentCommit,
  signature: Uint8Array,
  updatedTreeHash: Uint8Array,
  confirmationTag: Uint8Array,
  h: Hash,
): Promise<GroupContext> {
  const interimTranscriptHash = await createInterimHash(groupContext.confirmedTranscriptHash, confirmationTag, h)
  const newConfirmedHash = await createConfirmedHash(
    interimTranscriptHash,
    { wireformat: wireformats[wireformat], content, signature },
    h,
  )

  return {
    ...groupContext,
    epoch: groupContext.epoch + 1n,
    treeHash: updatedTreeHash,
    confirmedTranscriptHash: newConfirmedHash,
  }
}

/** @public */
export async function joinGroup(params: {
  context: MlsContext
  welcome: Welcome
  keyPackage: KeyPackage
  privateKeys: PrivateKeyPackage
  ratchetTree?: RatchetTree
}): Promise<ClientState> {
  const res = await joinGroupInternal(params)

  return res.state
}

/** @public */
export interface JoinGroupResult {
  state: ClientState
  groupInfoExtensions: GroupInfoExtension[]
}

export async function joinGroupInternal(params: {
  context: MlsContext
  welcome: Welcome
  keyPackage: KeyPackage
  privateKeys: PrivateKeyPackage
  ratchetTree?: RatchetTree
  resumingFromState?: ClientState
}): Promise<JoinGroupResult> {
  const context = params.context
  const welcome = params.welcome
  const keyPackage = params.keyPackage
  const privateKeys = params.privateKeys

  const pskSearch = makePskIndex(params.resumingFromState, context.externalPsks ?? {})
  const authService = context.authService
  const cs = context.cipherSuite
  const clientConfig = context.clientConfig ?? defaultClientConfig

  const ratchetTree = params.ratchetTree
  const resumingFromState = params.resumingFromState

  const keyPackageRef = await makeKeyPackageRef(keyPackage, cs.hash)
  const privKey = await cs.hpke.importPrivateKey(privateKeys.initPrivateKey)
  const groupSecrets = await decryptGroupSecrets(privKey, keyPackageRef, welcome, cs.hpke)

  if (groupSecrets === undefined) throw new CodecError("Could not decode group secrets")

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const [pskSecret, pskIds] = await accumulatePskSecret(groupSecrets.psks, pskSearch, cs, zeroes)

  const gi = await decryptGroupInfo(welcome, groupSecrets.joinerSecret, pskSecret, cs)
  if (gi === undefined) throw new CodecError("Could not decode group info")

  const resumptionPsk = pskIds.find((id) => id.psktype === pskTypes.resumption)
  if (resumptionPsk !== undefined) {
    if (resumingFromState === undefined) throw new ValidationError("No prior state passed for resumption")

    if (resumptionPsk.pskEpoch !== resumingFromState.groupContext.epoch) throw new ValidationError("Epoch mismatch")

    if (!constantTimeEqual(resumptionPsk.pskGroupId, resumingFromState.groupContext.groupId))
      throw new ValidationError("old groupId mismatch")

    if (gi.groupContext.epoch !== 1n) throw new ValidationError("Resumption must be started at epoch 1")

    if (resumptionPsk.usage === resumptionPSKUsages.reinit) {
      if (resumingFromState.groupActiveState.kind !== "suspendedPendingReinit")
        throw new ValidationError("Found reinit psk but no old suspended clientState")

      if (!constantTimeEqual(resumingFromState.groupActiveState.reinit.groupId, gi.groupContext.groupId))
        throw new ValidationError("new groupId mismatch")

      if (resumingFromState.groupActiveState.reinit.version !== gi.groupContext.version)
        throw new ValidationError("Version mismatch")

      if (resumingFromState.groupActiveState.reinit.cipherSuite !== gi.groupContext.cipherSuite)
        throw new ValidationError("Ciphersuite mismatch")

      if (!extensionsEqual(resumingFromState.groupActiveState.reinit.extensions, gi.groupContext.extensions))
        throw new ValidationError("Extensions mismatch")
    }
  }

  const allExtensionsSupported = extensionsSupportedByCapabilities(
    gi.groupContext.extensions,
    keyPackage.leafNode.capabilities,
  )
  if (!allExtensionsSupported) throw new UsageError("client does not support every extension in the GroupContext")

  const tree = ratchetTreeFromExtension(gi) ?? ratchetTree

  if (tree === undefined) throw new UsageError("No RatchetTree passed and no ratchet_tree extension")

  const signerNode = tree[leafToNodeIndex(toLeafIndex(gi.signer))]

  if (signerNode === undefined) {
    throw new ValidationError("Could not find signer leafNode")
  }
  if (signerNode.nodeType === nodeTypes.parent) throw new ValidationError("Expected non blank leaf node")

  const credentialVerified = await authService.validateCredential(
    signerNode.leaf.credential,
    signerNode.leaf.signaturePublicKey,
  )

  if (credentialVerified.kind === "error")
    throw new ValidationError(`Could not validate credential: ${credentialVerified.error}`)

  const groupInfoSignatureVerified = await verifyGroupInfoSignature(
    gi,
    signerNode.leaf.signaturePublicKey,
    cs.signature,
  )

  if (!groupInfoSignatureVerified) throw new CryptoVerificationError("Could not verify groupInfo signature")

  if (gi.groupContext.cipherSuite !== keyPackage.cipherSuite)
    throw new ValidationError("cipher suite in the GroupInfo does not match the cipher_suite in the KeyPackage")

  const treeHashCache: TreeHashCache = []

  throwIfDefined(
    await validateRatchetTree(
      tree,
      gi.groupContext,
      clientConfig.lifetimeConfig,
      authService,
      gi.groupContext.treeHash,
      cs,
      treeHashCache,
    ),
  )

  const newLeaf = findLeafIndex(tree, keyPackage.leafNode)

  if (newLeaf === undefined) throw new ValidationError("Could not find own leaf when processing welcome")

  const privateKeyPath: PrivateKeyPath = {
    leafIndex: newLeaf,
    privateKeys: { [leafToNodeIndex(newLeaf)]: privateKeys.hpkePrivateKey },
  }

  const ancestorNodeIndex = firstCommonAncestor(tree, newLeaf, toLeafIndex(gi.signer))

  const updatedPkp =
    groupSecrets.pathSecret === undefined
      ? privateKeyPath
      : mergePrivateKeyPaths(
          await toPrivateKeyPath(
            await pathToRoot(tree, ancestorNodeIndex, groupSecrets.pathSecret, cs.kdf),
            newLeaf,
            cs,
          ),
          privateKeyPath,
        )

  const [keySchedule, encryptionSecret] = await deriveKeySchedule(
    groupSecrets.joinerSecret,
    pskSecret,
    gi.groupContext,
    cs.kdf,
  )

  const confirmationTagVerified = await verifyGroupInfoConfirmationTag(gi, groupSecrets.joinerSecret, pskSecret, cs)

  if (!confirmationTagVerified) throw new CryptoVerificationError("Could not verify confirmation tag")

  const secretTree = createSecretTree(leafWidth(tree.length), encryptionSecret)

  zeroOutUint8Array(groupSecrets.joinerSecret)

  return {
    state: {
      groupContext: gi.groupContext,
      ratchetTree: tree,
      privatePath: updatedPkp,
      signaturePrivateKey: privateKeys.signaturePrivateKey,
      confirmationTag: gi.confirmationTag,
      unappliedProposals: {},
      keySchedule,
      secretTree,
      historicalReceiverData: new Map(),
      groupActiveState: { kind: "active" },
      treeHashCache,
    },
    groupInfoExtensions: gi.extensions,
  }
}

/** @public */
export async function joinGroupWithExtensions(params: {
  context: MlsContext
  welcome: Welcome
  keyPackage: KeyPackage
  privateKeys: PrivateKeyPackage
  ratchetTree?: RatchetTree
}): Promise<JoinGroupResult> {
  return joinGroupInternal(params)
}

/** @public */
export interface CreateGroupParams {
  context: MlsContext
  groupId: Uint8Array
  keyPackage: KeyPackage
  privateKeyPackage: PrivateKeyPackage
  extensions?: GroupContextExtension[]
}

/** @public */
export async function createGroup(params: CreateGroupParams): Promise<ClientState> {
  const { context, groupId, keyPackage, privateKeyPackage } = params
  const extensions = params.extensions ?? []
  const authService = context.authService
  const cs = context.cipherSuite
  const ratchetTree: RatchetTree = [{ nodeType: nodeTypes.leaf, leaf: keyPackage.leafNode }]

  const privatePath: PrivateKeyPath = {
    leafIndex: 0,
    privateKeys: { [0]: privateKeyPackage.hpkePrivateKey },
  }

  const confirmedTranscriptHash = new Uint8Array()

  const groupContext: GroupContext = {
    version: protocolVersions.mls10,
    cipherSuite: cs.id,
    epoch: 0n,
    treeHash: await treeHashRoot(ratchetTree, cs.hash),
    groupId,
    extensions,
    confirmedTranscriptHash,
  }

  throwIfDefined(await validateExternalSenders(extensions, authService))

  const epochSecret = cs.rng.randomBytes(cs.kdf.size)

  const keySchedule = await initializeKeySchedule(epochSecret, cs.kdf)

  const confirmationTag = await createConfirmationTag(keySchedule.confirmationKey, confirmedTranscriptHash, cs.hash)

  const encryptionSecret = await deriveSecret(epochSecret, "encryption", cs.kdf)

  const secretTree = createSecretTree(1, encryptionSecret)

  zeroOutUint8Array(epochSecret)

  return {
    ratchetTree,
    keySchedule,
    secretTree,
    privatePath,
    signaturePrivateKey: privateKeyPackage.signaturePrivateKey,
    unappliedProposals: {},
    historicalReceiverData: new Map(),
    groupContext,
    confirmationTag,
    groupActiveState: { kind: "active" },
    treeHashCache: [],
  }
}

export async function exportSecret(
  publicKey: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<{ enc: Uint8Array; secret: Uint8Array }> {
  return cs.hpke.exportSecret(
    await cs.hpke.importPublicKey(publicKey),
    new TextEncoder().encode("MLS 1.0 external init secret"),
    cs.kdf.size,
    new Uint8Array(),
  )
}

async function importSecret(privateKey: Uint8Array, kemOutput: Uint8Array, cs: CiphersuiteImpl): Promise<Uint8Array> {
  return cs.hpke.importSecret(
    await cs.hpke.importPrivateKey(privateKey),
    new TextEncoder().encode("MLS 1.0 external init secret"),
    kemOutput,
    cs.kdf.size,
    new Uint8Array(),
  )
}

async function applyTreeMutations(
  mutableTree: RatchetTree,
  grouped: PreprocessedProposals,
): Promise<[LeafIndex, KeyPackage][]> {
  for (const [leafIndex, proposal] of grouped.leafValidation.leafChanges) {
    if (leafIndex !== grouped.committerLeafIndex) {
      updateLeafNodeMutable(mutableTree, proposal.newLeafNode, leafToNodeIndex(leafIndex))
    }
  }

  grouped.leafValidation.removals.forEach((removed) => {
    removeLeafNodeMutable(mutableTree, toLeafIndex(removed))
  })

  const addedLNs = new Array<[LeafIndex, KeyPackage]>(grouped.leafValidation.adds.length)

  for (const [index, add] of grouped.leafValidation.adds.entries()) {
    const leafNodeIndex = addLeafNodeMutable(mutableTree, add.keyPackage.leafNode)
    addedLNs[index] = [nodeToLeafIndex(leafNodeIndex), add.keyPackage]
  }

  return addedLNs
}

export async function processProposal(
  state: ClientState,
  content: AuthenticatedContent,
  proposal: Proposal,
  senderLeafIndex: LeafIndex | undefined,
  clientConfig: ClientConfig,
  authService: AuthenticationService,
  impl: CiphersuiteImpl,
): Promise<ClientState> {
  //Whenever a new credential is introduced in the group, it MUST be validated with the AS. In particular, at the following events in the protocol:
  //When a member receives an Add proposal adding a member to the group

  const requiredCapabilities = findExtension(defaultExtensionTypes.required_capabilities, state.groupContext.extensions)

  if (isDefaultProposal(proposal)) {
    switch (proposal.proposalType) {
      case defaultProposalTypes.add:
        await validateAddProposal(proposal, state, requiredCapabilities, clientConfig, authService, impl)
        break
      case defaultProposalTypes.update:
        if (senderLeafIndex === undefined) throw new ValidationError("Received an Update proposal from a non-member")
        await validateUpdateProposal(
          proposal,
          senderLeafIndex,
          requiredCapabilities,
          clientConfig,
          state.groupContext,
          state.ratchetTree,
          authService,
          impl,
        )
        break
      case defaultProposalTypes.group_context_extensions:
        if (senderLeafIndex === undefined)
          throw new ValidationError("Received a GroupContextExtensions proposal from a non-member")
        await validateGroupContextExtensionProposal(
          proposal,
          senderLeafIndex,
          state,
          clientConfig,
          authService,
          state.ratchetTree,
          impl,
        )
        break
    }
  }
  return saveProposal(state, content, proposal, impl.hash)
}

/**
 * Validates an AddProposal that is not part of a commit
 */
async function validateAddProposal(
  proposal: ProposalAdd,
  state: ClientState,
  requiredCapabilities: RequiredCapabilities | undefined,
  clientConfig: ClientConfig,
  authService: AuthenticationService,
  impl: CiphersuiteImpl,
): Promise<void> {
  const validationInput = {
    adds: [{ authenticated: false, sentByClient: false, keyPackage: proposal.add.keyPackage }],
    leafChanges: new Map(),
    removals: new Set<LeafIndex>(),
    groupContextExtensions: undefined,
  }

  const authIndices = await validateProposalsExtractAuthIndices(
    validationInput,
    [],
    requiredCapabilities,
    state.groupContext,
    state.groupContext.extensions,
    clientConfig,
    authService.batchSize,
    impl.signature,
  )

  throwIfDefined(
    validateProposalsAgainstFullTree(
      state.ratchetTree,
      authIndices.treeIndexes,
      validationInput,
      clientConfig.keyPackageEqualityConfig,
      new Set(),
      undefined,
    ),
  )

  if (authIndices.authInput.length > 0) {
    const authResult = await authenticateCredentials(authIndices.authInput, authService)
    if (authResult.kind === "error") {
      throw new AuthenticationError(authResult.error)
    }
  }
}

/**
 * Validates an UpdateProposal that is not part of a commit
 */
async function validateUpdateProposal(
  proposal: ProposalUpdate,
  senderLeafIndex: LeafIndex,
  requiredCapabilities: RequiredCapabilities | undefined,
  clientConfig: ClientConfig,
  groupContext: GroupContext,
  tree: RatchetTree,
  authService: AuthenticationService,
  impl: CiphersuiteImpl,
): Promise<void> {
  const leafNodeIndex = leafToNodeIndex(senderLeafIndex)
  const oldLeafNode = tree[leafNodeIndex]
  if (oldLeafNode?.nodeType !== nodeTypes.leaf) throw new InternalError("Tried to update a non-leaf node")

  const validationInput = {
    adds: [],
    leafChanges: new Map([
      [senderLeafIndex, { oldLeafNode: oldLeafNode.leaf, newLeafNode: proposal.update.leafNode, authenticated: false }],
    ]),
    removals: new Set<LeafIndex>(),
    groupContextExtensions: undefined,
  }

  const authIndices = await validateProposalsExtractAuthIndices(
    validationInput,
    [],
    requiredCapabilities,
    groupContext,
    groupContext.extensions,
    clientConfig,
    authService.batchSize,
    impl.signature,
  )

  throwIfDefined(
    validateProposalsAgainstFullTree(
      tree,
      authIndices.treeIndexes,
      validationInput,
      clientConfig.keyPackageEqualityConfig,
      new Set(),
      undefined,
    ),
  )

  if (authIndices.authInput.length > 0) {
    const authResult = await authenticateCredentials(authIndices.authInput, authService)
    if (authResult.kind === "error") {
      throw new AuthenticationError(authResult.error)
    }
  }
}

/**
 * Validates an ProposalGroupContextExtensions that is not part of a commit
 */
async function validateGroupContextExtensionProposal(
  proposal: ProposalGroupContextExtensions,
  senderLeafIndex: LeafIndex,
  state: ClientState,
  clientConfig: ClientConfig,
  authService: AuthenticationService,
  tree: RatchetTree,
  cs: CiphersuiteImpl,
): Promise<void> {
  const leafNodeIndex = leafToNodeIndex(senderLeafIndex)
  const oldLeafNode = tree[leafNodeIndex]
  if (oldLeafNode?.nodeType !== nodeTypes.leaf) throw new InternalError("Tried to update a non-leaf node")

  const gce = parseGce(proposal.groupContextExtensions, false)

  const validationInput = {
    adds: [],
    leafChanges: new Map(),
    groupContextExtensions: gce,
    removals: new Set<LeafIndex>(),
  }
  const authIndices = await validateProposalsExtractAuthIndices(
    validationInput,
    [],
    gce.newRequiredCapabilities,
    state.groupContext,
    gce.groupContextExtensions,
    clientConfig,
    authService.batchSize,
    cs.signature,
  )

  throwIfDefined(
    validateProposalsAgainstFullTree(
      tree,
      authIndices.treeIndexes,
      validationInput,
      clientConfig.keyPackageEqualityConfig,
      new Set(),
      gce,
    ),
  )

  if (authIndices.authInput.length > 0) {
    const authResult = await authenticateCredentials(authIndices.authInput, authService)
    if (authResult.kind === "error") {
      throw new AuthenticationError(authResult.error)
    }
  }
}

export async function saveProposal(
  state: ClientState,
  content: AuthenticatedContent,
  proposal: Proposal,
  h: Hash,
): Promise<ClientState> {
  const ref = await makeProposalRef(content, h)
  return {
    ...state,
    unappliedProposals: addUnappliedProposal(
      ref,
      state.unappliedProposals,
      proposal,
      getSenderLeafNodeIndex(content.content.sender),
    ),
  }
}

export function addHistoricalReceiverData(
  state: ClientState,
  clientConfig: ClientConfig,
): [Map<bigint, EpochReceiverData>, Uint8Array[]] {
  const withNew = addToMap(state.historicalReceiverData, state.groupContext.epoch, {
    secretTree: state.secretTree,
    ratchetTree: state.ratchetTree,
    senderDataSecret: state.keySchedule.senderDataSecret,
    groupContext: state.groupContext,
    resumptionPsk: state.keySchedule.resumptionPsk,
  })

  const epochs = [...withNew.keys()]

  const result: [Map<bigint, EpochReceiverData>, Uint8Array[]] =
    epochs.length >= clientConfig.keyRetentionConfig.retainKeysForEpochs
      ? removeOldHistoricalReceiverData(withNew, clientConfig.keyRetentionConfig.retainKeysForEpochs)
      : [withNew, []]

  return result
}

function removeOldHistoricalReceiverData(
  historicalReceiverData: Map<bigint, EpochReceiverData>,
  max: number,
): [Map<bigint, EpochReceiverData>, Uint8Array[]] {
  const sortedEpochs = [...historicalReceiverData.keys()].sort((a, b) => (a < b ? -1 : 1))

  const cutoff = sortedEpochs.length - max

  const toBeDeleted: Uint8Array[] = []
  for (let n = 0; n < cutoff; n++) {
    appendSecretTreeValues(historicalReceiverData.get(sortedEpochs[n]!)!.secretTree, toBeDeleted)
  }

  const map = new Map(sortedEpochs.slice(-max).map((epoch) => [epoch, historicalReceiverData.get(epoch)!]))

  return [map, toBeDeleted]
}
