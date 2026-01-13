import { AuthenticatedContent, makeProposalRef } from "./authenticatedContent.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Hash } from "./crypto/hash.js"
import { Extension, extensionsEqual, extensionsSupportedByCapabilities } from "./extension.js"
import { createConfirmationTag, FramedContentCommit } from "./framedContent.js"
import { decodeGroupContext, GroupContext, groupContextEncoder } from "./groupContext.js"
import { ratchetTreeFromExtension, verifyGroupInfoConfirmationTag, verifyGroupInfoSignature } from "./groupInfo.js"
import { KeyPackage, makeKeyPackageRef, PrivateKeyPackage, verifyKeyPackage } from "./keyPackage.js"
import {
  decodeKeySchedule,
  deriveKeySchedule,
  initializeKeySchedule,
  KeySchedule,
  keyScheduleEncoder,
} from "./keySchedule.js"
import { pskIdEncoder, PreSharedKeyID, pskTypes, resumptionPSKUsages } from "./presharedkey.js"

import {
  addLeafNode,
  decodeRatchetTree,
  findBlankLeafNodeIndexOrExtend,
  findLeafIndex,
  ratchetTreeEncoder,
  removeLeafNode,
  updateLeafNode,
} from "./ratchetTree.js"
import { RatchetTree } from "./ratchetTree.js"
import { allSecretTreeValues, createSecretTree, decodeSecretTree, SecretTree, secretTreeEncoder } from "./secretTree.js"
import { createConfirmedHash, createInterimHash } from "./transcriptHash.js"
import { treeHashRoot } from "./treeHash.js"
import {
  directPath,
  isLeaf,
  LeafIndex,
  leafToNodeIndex,
  leafWidth,
  nodeToLeafIndex,
  toLeafIndex,
  toNodeIndex,
} from "./treemath.js"
import { firstCommonAncestor } from "./updatePath.js"
import { bytesToBase64, zeroOutUint8Array } from "./util/byteArray.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"
import { decryptGroupInfo, decryptGroupSecrets, Welcome } from "./welcome.js"
import { WireformatName, wireformats } from "./wireformat.js"
import { ProposalOrRef, proposalOrRefTypes } from "./proposalOrRefType.js"
import {
  isDefaultProposal,
  Proposal,
  ProposalAdd,
  ProposalExternalInit,
  ProposalGroupContextExtensions,
  ProposalPSK,
  ProposalReinit,
  ProposalRemove,
  ProposalUpdate,
  Reinit,
  Remove,
} from "./proposal.js"
import { defaultProposalTypes } from "./defaultProposalType.js"
import { defaultExtensionTypes } from "./defaultExtensionType.js"
import { pathToRoot } from "./pathSecrets.js"
import {
  PrivateKeyPath,
  decodePrivateKeyPath,
  mergePrivateKeyPaths,
  privateKeyPathEncoder,
  toPrivateKeyPath,
} from "./privateKeyPath.js"
import {
  UnappliedProposals,
  addUnappliedProposal,
  ProposalWithSender,
  unappliedProposalsEncoder,
  decodeUnappliedProposals,
} from "./unappliedProposals.js"
import { accumulatePskSecret, PskIndex } from "./pskIndex.js"
import { getSenderLeafNodeIndex } from "./sender.js"
import { addToMap } from "./util/addToMap.js"
import {
  CryptoVerificationError,
  CodecError,
  InternalError,
  UsageError,
  ValidationError,
  MlsError,
} from "./mlsError.js"
import { Signature } from "./crypto/signature.js"
import {
  LeafNode,
  LeafNodeCommit,
  LeafNodeKeyPackage,
  LeafNodeUpdate,
  verifyLeafNodeSignature,
  verifyLeafNodeSignatureKeyPackage,
} from "./leafNode.js"
import { leafNodeSources } from "./leafNodeSource.js"
import { nodeTypes } from "./nodeType.js"
import { protocolVersions } from "./protocolVersion.js"
import { decodeRequiredCapabilities, RequiredCapabilities } from "./requiredCapabilities.js"
import { Capabilities } from "./capabilities.js"
import { verifyParentHashes } from "./parentHash.js"
import { AuthenticationService } from "./authenticationService.js"
import { LifetimeConfig } from "./lifetimeConfig.js"
import { KeyPackageEqualityConfig } from "./keyPackageEqualityConfig.js"
import { ClientConfig, defaultClientConfig } from "./clientConfig.js"
import { decodeExternalSender } from "./externalSender.js"
import { arraysEqual } from "./util/array.js"
import { BufferEncoder, contramapBufferEncoders, encode } from "./codec/tlsEncoder.js"

import { bigintMapEncoder, decodeBigintMap, decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { decodeGroupActiveState, GroupActiveState, groupActiveStateEncoder } from "./groupActiveState.js"
import { decodeEpochReceiverData, EpochReceiverData, epochReceiverDataEncoder } from "./epochReceiverData.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { deriveSecret } from "./crypto/kdf.js"

/** @public */
export type ClientState = GroupState & { clientConfig: ClientConfig }

/** @public */
export interface GroupState {
  groupContext: GroupContext
  keySchedule: KeySchedule
  secretTree: SecretTree
  ratchetTree: RatchetTree
  privatePath: PrivateKeyPath
  signaturePrivateKey: Uint8Array
  unappliedProposals: UnappliedProposals
  confirmationTag: Uint8Array
  historicalReceiverData: Map<bigint, EpochReceiverData>
  groupActiveState: GroupActiveState
}

/** @public */
export const groupStateEncoder: BufferEncoder<GroupState> = contramapBufferEncoders(
  [
    groupContextEncoder,
    keyScheduleEncoder,
    secretTreeEncoder,
    ratchetTreeEncoder,
    privateKeyPathEncoder,
    varLenDataEncoder,
    unappliedProposalsEncoder,
    varLenDataEncoder,
    bigintMapEncoder(epochReceiverDataEncoder),
    groupActiveStateEncoder,
  ],
  (state) =>
    [
      state.groupContext,
      state.keySchedule,
      state.secretTree,
      state.ratchetTree,
      state.privatePath,
      state.signaturePrivateKey,
      state.unappliedProposals,
      state.confirmationTag,
      state.historicalReceiverData,
      state.groupActiveState,
    ] as const,
)

/** @public */
export const decodeGroupState: Decoder<GroupState> = mapDecoders(
  [
    decodeGroupContext,
    decodeKeySchedule,
    decodeSecretTree,
    decodeRatchetTree,
    decodePrivateKeyPath,
    decodeVarLenData,
    decodeUnappliedProposals,
    decodeVarLenData,
    decodeBigintMap(decodeEpochReceiverData),
    decodeGroupActiveState,
  ],
  (
    groupContext,
    keySchedule,
    secretTree,
    ratchetTree,
    privatePath,
    signaturePrivateKey,
    unappliedProposals,
    confirmationTag,
    historicalReceiverData,
    groupActiveState,
  ) => ({
    groupContext,
    keySchedule,
    secretTree,
    ratchetTree,
    privatePath,
    signaturePrivateKey,
    unappliedProposals,
    confirmationTag,
    historicalReceiverData,
    groupActiveState,
  }),
)

export function getOwnLeafNode(state: ClientState): LeafNode {
  const idx = leafToNodeIndex(toLeafIndex(state.privatePath.leafIndex))
  const leaf = state.ratchetTree[idx]
  if (leaf?.nodeType !== nodeTypes.leaf) throw new InternalError("Expected leaf node")
  return leaf.leaf
}

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

export interface Proposals {
  [defaultProposalTypes.add]: { senderLeafIndex: number | undefined; proposal: ProposalAdd }[]
  [defaultProposalTypes.update]: { senderLeafIndex: number | undefined; proposal: ProposalUpdate }[]
  [defaultProposalTypes.remove]: { senderLeafIndex: number | undefined; proposal: ProposalRemove }[]
  [defaultProposalTypes.psk]: { senderLeafIndex: number | undefined; proposal: ProposalPSK }[]
  [defaultProposalTypes.reinit]: { senderLeafIndex: number | undefined; proposal: ProposalReinit }[]
  [defaultProposalTypes.external_init]: { senderLeafIndex: number | undefined; proposal: ProposalExternalInit }[]
  [defaultProposalTypes.group_context_extensions]: {
    senderLeafIndex: number | undefined
    proposal: ProposalGroupContextExtensions
  }[]
}

const emptyProposals: Proposals = {
  [defaultProposalTypes.add]: [],
  [defaultProposalTypes.update]: [],
  [defaultProposalTypes.remove]: [],
  [defaultProposalTypes.psk]: [],
  [defaultProposalTypes.reinit]: [],
  [defaultProposalTypes.external_init]: [],
  [defaultProposalTypes.group_context_extensions]: [],
}

function flattenExtensions(groupContextExtensions: { proposal: ProposalGroupContextExtensions }[]): Extension[] {
  return groupContextExtensions.reduce((acc, { proposal }) => {
    return [...acc, ...proposal.groupContextExtensions.extensions]
  }, [] as Extension[])
}

async function validateProposals(
  p: Proposals,
  committerLeafIndex: number | undefined,
  groupContext: GroupContext,
  config: KeyPackageEqualityConfig,
  authService: AuthenticationService,
  tree: RatchetTree,
): Promise<MlsError | undefined> {
  const containsUpdateByCommitter = p[defaultProposalTypes.update].some(
    (o) => o.senderLeafIndex !== undefined && o.senderLeafIndex === committerLeafIndex,
  )

  if (containsUpdateByCommitter)
    return new ValidationError("Commit cannot contain an update proposal sent by committer")

  const containsRemoveOfCommitter = p[defaultProposalTypes.remove].some(
    (o) => o.proposal.remove.removed === committerLeafIndex,
  )

  if (containsRemoveOfCommitter)
    return new ValidationError("Commit cannot contain a remove proposal removing committer")

  const multipleUpdateRemoveForSameLeaf =
    p[defaultProposalTypes.update].some(
      ({ senderLeafIndex: a }, indexA) =>
        p[defaultProposalTypes.update].some(({ senderLeafIndex: b }, indexB) => a === b && indexA !== indexB) ||
        p[defaultProposalTypes.remove].some((r) => r.proposal.remove.removed === a),
    ) ||
    p[defaultProposalTypes.remove].some(
      (a, indexA) =>
        p[defaultProposalTypes.remove].some(
          (b, indexB) => b.proposal.remove.removed === a.proposal.remove.removed && indexA !== indexB,
        ) ||
        p[defaultProposalTypes.update].some(({ senderLeafIndex }) => a.proposal.remove.removed === senderLeafIndex),
    )

  if (multipleUpdateRemoveForSameLeaf)
    return new ValidationError(
      "Commit cannot contain multiple update and/or remove proposals that apply to the same leaf",
    )

  const multipleAddsContainSameKeypackage = p[defaultProposalTypes.add].some(({ proposal: a }, indexA) =>
    p[defaultProposalTypes.add].some(
      ({ proposal: b }, indexB) => config.compareKeyPackages(a.add.keyPackage, b.add.keyPackage) && indexA !== indexB,
    ),
  )

  if (multipleAddsContainSameKeypackage)
    return new ValidationError(
      "Commit cannot contain multiple Add proposals that contain KeyPackages that represent the same client",
    )

  // checks if there is an Add proposal with a KeyPackage that matches a client already in the group
  // unless there is a Remove proposal in the list removing the matching client from the group.
  const addsContainExistingKeypackage = p[defaultProposalTypes.add].some(({ proposal }) =>
    tree.some(
      (node, nodeIndex) =>
        node !== undefined &&
        node.nodeType === nodeTypes.leaf &&
        config.compareKeyPackageToLeafNode(proposal.add.keyPackage, node.leaf) &&
        p[defaultProposalTypes.remove].every(
          (r) => r.proposal.remove.removed !== nodeToLeafIndex(toNodeIndex(nodeIndex)),
        ),
    ),
  )

  if (addsContainExistingKeypackage)
    return new ValidationError("Commit cannot contain an Add proposal for someone already in the group")

  const everyLeafSupportsGroupExtensions = p[defaultProposalTypes.add].every(({ proposal }) =>
    extensionsSupportedByCapabilities(groupContext.extensions, proposal.add.keyPackage.leafNode.capabilities),
  )

  if (!everyLeafSupportsGroupExtensions)
    return new ValidationError("Added leaf node that doesn't support extension in GroupContext")

  const multiplePskWithSamePskId = p[defaultProposalTypes.psk].some((a, indexA) =>
    p[defaultProposalTypes.psk].some(
      (b, indexB) =>
        constantTimeEqual(
          encode(pskIdEncoder, a.proposal.psk.preSharedKeyId),
          encode(pskIdEncoder, b.proposal.psk.preSharedKeyId),
        ) && indexA !== indexB,
    ),
  )

  if (multiplePskWithSamePskId)
    return new ValidationError("Commit cannot contain PreSharedKey proposals that reference the same PreSharedKeyID")

  const multipleGroupContextExtensions = p[defaultProposalTypes.group_context_extensions].length > 1

  if (multipleGroupContextExtensions)
    return new ValidationError("Commit cannot contain multiple GroupContextExtensions proposals")

  const allExtensions = flattenExtensions(p[defaultProposalTypes.group_context_extensions])

  const requiredCapabilities = allExtensions.find(
    (e) => e.extensionType === defaultExtensionTypes.required_capabilities,
  )

  if (requiredCapabilities !== undefined) {
    const caps = decodeRequiredCapabilities(requiredCapabilities.extensionData, 0)
    if (caps === undefined) return new CodecError("Could not decode required_capabilities")

    const everyLeafSupportsCapabilities = tree
      .filter((n) => n !== undefined && n.nodeType === nodeTypes.leaf)
      .every((l) => capabiltiesAreSupported(caps[0], l.leaf.capabilities))

    if (!everyLeafSupportsCapabilities) return new ValidationError("Not all members support required capabilities")

    const allAdditionsSupportCapabilities = p[defaultProposalTypes.add].every((a) =>
      capabiltiesAreSupported(caps[0], a.proposal.add.keyPackage.leafNode.capabilities),
    )

    if (!allAdditionsSupportCapabilities)
      return new ValidationError("Commit contains add proposals of member without required capabilities")
  }

  return await validateExternalSenders(allExtensions, authService)
}

async function validateExternalSenders(
  extensions: Extension[],
  authService: AuthenticationService,
): Promise<MlsError | undefined> {
  const externalSenders = extensions.filter((e) => e.extensionType === defaultExtensionTypes.external_senders)
  for (const externalSender of externalSenders) {
    const decoded = decodeExternalSender(externalSender.extensionData, 0)
    if (decoded === undefined) return new CodecError("Could not decode external_senders")

    const validCredential = await authService.validateCredential(decoded[0].credential, decoded[0].signaturePublicKey)
    if (!validCredential) return new ValidationError("Could not validate external credential")
  }
}

function capabiltiesAreSupported(caps: RequiredCapabilities, cs: Capabilities): boolean {
  return (
    caps.credentialTypes.every((c) => cs.credentials.includes(c)) &&
    caps.extensionTypes.every((e) => cs.extensions.includes(e)) &&
    caps.proposalTypes.every((p) => cs.proposals.includes(p))
  )
}

export async function validateRatchetTree(
  tree: RatchetTree,
  groupContext: GroupContext,
  config: LifetimeConfig,
  authService: AuthenticationService,
  treeHash: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<MlsError | undefined> {
  const hpkeKeys = new Set<string>()
  const signatureKeys = new Set<string>()
  const credentialTypes = new Set<number>()
  for (const [i, n] of tree.entries()) {
    const nodeIndex = toNodeIndex(i)
    if (n?.nodeType === nodeTypes.leaf) {
      if (!isLeaf(nodeIndex)) return new ValidationError("Received Ratchet Tree is not structurally sound")

      const hpkeKey = bytesToBase64(n.leaf.hpkePublicKey)
      if (hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")
      else hpkeKeys.add(hpkeKey)

      const signatureKey = bytesToBase64(n.leaf.signaturePublicKey)
      if (signatureKeys.has(signatureKey)) return new ValidationError("signature keys not unique")
      else signatureKeys.add(signatureKey)

      {
        credentialTypes.add(n.leaf.credential.credentialType)
      }

      const err =
        n.leaf.leafNodeSource === leafNodeSources.key_package
          ? await validateLeafNodeKeyPackage(n.leaf, groupContext, false, config, authService, cs.signature)
          : await validateLeafNodeUpdateOrCommit(
              n.leaf,
              nodeToLeafIndex(nodeIndex),
              groupContext,
              authService,
              cs.signature,
            )

      if (err !== undefined) return err
    } else if (n?.nodeType === nodeTypes.parent) {
      if (isLeaf(nodeIndex)) return new ValidationError("Received Ratchet Tree is not structurally sound")

      const hpkeKey = bytesToBase64(n.parent.hpkePublicKey)
      if (hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")
      else hpkeKeys.add(hpkeKey)

      for (const unmergedLeaf of n.parent.unmergedLeaves) {
        const leafIndex = toLeafIndex(unmergedLeaf)
        const dp = directPath(leafToNodeIndex(leafIndex), leafWidth(tree.length))
        const nodeIndex = leafToNodeIndex(leafIndex)
        if (tree[nodeIndex]?.nodeType !== nodeTypes.leaf && !dp.includes(toNodeIndex(i)))
          return new ValidationError("Unmerged leaf did not represent a non-blank descendant leaf node")

        for (const parentIdx of dp) {
          const dpNode = tree[parentIdx]

          if (dpNode !== undefined) {
            if (dpNode.nodeType !== nodeTypes.parent) return new InternalError("Expected parent node")

            if (!arraysEqual(dpNode.parent.unmergedLeaves, n.parent.unmergedLeaves))
              return new ValidationError("non-blank intermediate node must list leaf node in its unmerged_leaves")
          }
        }
      }
    }
  }

  for (const n of tree) {
    if (n?.nodeType === nodeTypes.leaf) {
      for (const credentialType of credentialTypes) {
        if (!n.leaf.capabilities.credentials.includes(credentialType))
          return new ValidationError("LeafNode has credential that is not supported by member of the group")
      }
    }
  }

  const parentHashesVerified = await verifyParentHashes(tree, cs.hash)

  if (!parentHashesVerified) return new CryptoVerificationError("Unable to verify parent hash")

  if (!constantTimeEqual(treeHash, await treeHashRoot(tree, cs.hash)))
    return new ValidationError("Unable to verify tree hash")
}

export async function validateLeafNodeUpdateOrCommit(
  leafNode: LeafNodeCommit | LeafNodeUpdate,
  leafIndex: number,
  groupContext: GroupContext,
  authService: AuthenticationService,
  s: Signature,
): Promise<MlsError | undefined> {
  const signatureValid = await verifyLeafNodeSignature(leafNode, groupContext.groupId, leafIndex, s)

  if (!signatureValid) return new CryptoVerificationError("Could not verify leaf node signature")

  const commonError = await validateLeafNodeCommon(leafNode, groupContext, authService)

  if (commonError !== undefined) return commonError
}

export function throwIfDefined(err: MlsError | undefined): void {
  if (err !== undefined) throw err
}

async function validateLeafNodeCommon(
  leafNode: LeafNode,
  groupContext: GroupContext,
  authService: AuthenticationService,
) {
  const credentialValid = await authService.validateCredential(leafNode.credential, leafNode.signaturePublicKey)

  if (!credentialValid) return new ValidationError("Could not validate credential")

  const requiredCapabilities = groupContext.extensions.find(
    (e) => e.extensionType === defaultExtensionTypes.required_capabilities,
  )

  if (requiredCapabilities !== undefined) {
    const caps = decodeRequiredCapabilities(requiredCapabilities.extensionData, 0)
    if (caps === undefined) return new CodecError("Could not decode required_capabilities")

    const leafSupportsCapabilities = capabiltiesAreSupported(caps[0], leafNode.capabilities)

    if (!leafSupportsCapabilities) return new ValidationError("LeafNode does not support required capabilities")
  }

  const extensionsSupported = extensionsSupportedByCapabilities(leafNode.extensions, leafNode.capabilities)

  if (!extensionsSupported) return new ValidationError("LeafNode contains extension not listed in capabilities")
}

async function validateLeafNodeKeyPackage(
  leafNode: LeafNodeKeyPackage,
  groupContext: GroupContext,
  sentByClient: boolean,
  config: LifetimeConfig,
  authService: AuthenticationService,
  s: Signature,
): Promise<MlsError | undefined> {
  const signatureValid = await verifyLeafNodeSignatureKeyPackage(leafNode, s)
  if (!signatureValid) return new CryptoVerificationError("Could not verify leaf node signature")

  //verify lifetime
  if (sentByClient || config.validateLifetimeOnReceive) {
    if (leafNode.leafNodeSource === leafNodeSources.key_package) {
      const currentTime = BigInt(Math.floor(Date.now() / 1000))
      if (leafNode.lifetime.notBefore > currentTime || leafNode.lifetime.notAfter < currentTime)
        return new ValidationError("Current time not within Lifetime")
    }
  }

  const commonError = await validateLeafNodeCommon(leafNode, groupContext, authService)

  if (commonError !== undefined) return commonError
}

export async function validateLeafNodeCredentialAndKeyUniqueness(
  tree: RatchetTree,
  leafNode: LeafNode,
  existingLeafIndex?: number,
): Promise<ValidationError | undefined> {
  const hpkeKeys = new Set<string>()
  const signatureKeys = new Set<string>()
  for (const [nodeIndex, node] of tree.entries()) {
    if (node?.nodeType === nodeTypes.leaf) {
      const credentialType = leafNode.credential.credentialType
      if (!node.leaf.capabilities.credentials.includes(credentialType)) {
        return new ValidationError("LeafNode has credential that is not supported by member of the group")
      }

      const hpkeKey = bytesToBase64(node.leaf.hpkePublicKey)
      if (hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")
      else hpkeKeys.add(hpkeKey)

      const signatureKey = bytesToBase64(node.leaf.signaturePublicKey)
      if (signatureKeys.has(signatureKey) && existingLeafIndex !== nodeToLeafIndex(toNodeIndex(nodeIndex)))
        return new ValidationError("signature keys not unique")
      else signatureKeys.add(signatureKey)
    } else if (node?.nodeType === nodeTypes.parent) {
      const hpkeKey = bytesToBase64(node.parent.hpkePublicKey)
      if (hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")
      else hpkeKeys.add(hpkeKey)
    }
  }
}

async function validateKeyPackage(
  kp: KeyPackage,
  groupContext: GroupContext,
  tree: RatchetTree,
  sentByClient: boolean,
  config: LifetimeConfig,
  authService: AuthenticationService,
  s: Signature,
): Promise<MlsError | undefined> {
  if (kp.cipherSuite !== groupContext.cipherSuite) return new ValidationError("Invalid CipherSuite")

  if (kp.version !== groupContext.version) return new ValidationError("Invalid mls version")

  const leafNodeConsistentWithTree = await validateLeafNodeCredentialAndKeyUniqueness(tree, kp.leafNode)

  if (leafNodeConsistentWithTree !== undefined) return leafNodeConsistentWithTree

  const leafNodeError = await validateLeafNodeKeyPackage(
    kp.leafNode,
    groupContext,
    sentByClient,
    config,
    authService,
    s,
  )
  if (leafNodeError !== undefined) return leafNodeError

  const signatureValid = await verifyKeyPackage(kp, s)
  if (!signatureValid) return new CryptoVerificationError("Invalid keypackage signature")

  if (constantTimeEqual(kp.initKey, kp.leafNode.hpkePublicKey))
    return new ValidationError("Cannot have identicial init and encryption keys")
}

function validateReinit(
  allProposals: ProposalWithSender[],
  reinit: Reinit,
  gc: GroupContext,
): ValidationError | undefined {
  if (allProposals.length !== 1) return new ValidationError("Reinit proposal needs to be commited by itself")

  if (reinit.version < gc.version)
    return new ValidationError("A ReInit proposal cannot use a version less than the version for the current group")
}

function validateExternalInit(grouped: Proposals): ValidationError | undefined {
  if (grouped[defaultProposalTypes.external_init].length > 1)
    return new ValidationError("Cannot contain more than one external_init proposal")

  if (grouped[defaultProposalTypes.remove].length > 1)
    return new ValidationError("Cannot contain more than one remove proposal")

  if (
    grouped[defaultProposalTypes.add].length > 0 ||
    grouped[defaultProposalTypes.group_context_extensions].length > 0 ||
    grouped[defaultProposalTypes.reinit].length > 0 ||
    grouped[defaultProposalTypes.update].length > 0
  )
    return new ValidationError("Invalid proposals")
}

function validateRemove(remove: Remove, tree: RatchetTree): MlsError | undefined {
  if (tree[leafToNodeIndex(toLeafIndex(remove.removed))] === undefined)
    return new ValidationError("Tried to remove empty leaf node")
}

export interface ApplyProposalsResult {
  tree: RatchetTree
  pskSecret: Uint8Array
  pskIds: PreSharedKeyID[]
  needsUpdatePath: boolean
  additionalResult: ApplyProposalsData
  selfRemoved: boolean
  allProposals: ProposalWithSender[]
}

export type ApplyProposalsData =
  | { kind: "memberCommit"; addedLeafNodes: [LeafIndex, KeyPackage][]; extensions: Extension[] }
  | { kind: "externalCommit"; externalInitSecret: Uint8Array; newMemberLeafIndex: LeafIndex }
  | { kind: "reinit"; reinit: Reinit }

export async function applyProposals(
  state: ClientState,
  proposals: ProposalOrRef[],
  committerLeafIndex: LeafIndex | undefined,
  pskSearch: PskIndex,
  sentByClient: boolean,
  cs: CiphersuiteImpl,
): Promise<ApplyProposalsResult> {
  const allProposals = proposals.reduce((acc, cur) => {
    if (cur.proposalOrRefType === proposalOrRefTypes.proposal)
      return [...acc, { proposal: cur.proposal, senderLeafIndex: committerLeafIndex }]

    const p = state.unappliedProposals[bytesToBase64(cur.reference)]
    if (p === undefined) throw new ValidationError("Could not find proposal with supplied reference")
    return [...acc, p]
  }, [] as ProposalWithSender[])

  const grouped = allProposals.reduce((acc, cur) => {
    //this skips any custom proposals
    if (isDefaultProposal(cur.proposal)) {
      const proposalType = cur.proposal.proposalType
      const proposals = acc[proposalType] ?? []
      return { ...acc, [cur.proposal.proposalType]: [...proposals, cur] }
    } else {
      return acc
    }
  }, emptyProposals)

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const isExternalInit = grouped[defaultProposalTypes.external_init].length > 0

  if (!isExternalInit) {
    if (grouped[defaultProposalTypes.reinit].length > 0) {
      const reinit = grouped[defaultProposalTypes.reinit].at(0)!.proposal.reinit

      throwIfDefined(validateReinit(allProposals, reinit, state.groupContext))

      return {
        tree: state.ratchetTree,
        pskSecret: zeroes,
        pskIds: [],
        needsUpdatePath: false,
        additionalResult: {
          kind: "reinit",
          reinit,
        },
        selfRemoved: false,
        allProposals,
      }
    }

    throwIfDefined(
      await validateProposals(
        grouped,
        committerLeafIndex,
        state.groupContext,
        state.clientConfig.keyPackageEqualityConfig,
        state.clientConfig.authService,
        state.ratchetTree,
      ),
    )

    const newExtensions = flattenExtensions(grouped[defaultProposalTypes.group_context_extensions])

    const [mutatedTree, addedLeafNodes] = await applyTreeMutations(
      state.ratchetTree,
      grouped,
      state.groupContext,
      sentByClient,
      state.clientConfig.authService,
      state.clientConfig.lifetimeConfig,
      cs.signature,
    )

    const [updatedPskSecret, pskIds] = await accumulatePskSecret(
      grouped[defaultProposalTypes.psk].map((p) => p.proposal.psk.preSharedKeyId),
      pskSearch,
      cs,
      zeroes,
    )

    const selfRemoved = mutatedTree[leafToNodeIndex(toLeafIndex(state.privatePath.leafIndex))] === undefined

    const needsUpdatePath =
      allProposals.length === 0 ||
      Object.values(grouped[defaultProposalTypes.update]).length > 1 ||
      Object.values(grouped[defaultProposalTypes.remove]).length > 1

    return {
      tree: mutatedTree,
      pskSecret: updatedPskSecret,
      additionalResult: {
        kind: "memberCommit" as const,
        addedLeafNodes,
        extensions: newExtensions,
      },
      pskIds,
      needsUpdatePath,
      selfRemoved,
      allProposals,
    }
  } else {
    throwIfDefined(validateExternalInit(grouped))

    const treeAfterRemove = grouped[defaultProposalTypes.remove].reduce((acc, { proposal }) => {
      return removeLeafNode(acc, toLeafIndex(proposal.remove.removed))
    }, state.ratchetTree)

    const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

    const [updatedPskSecret, pskIds] = await accumulatePskSecret(
      grouped[defaultProposalTypes.psk].map((p) => p.proposal.psk.preSharedKeyId),
      pskSearch,
      cs,
      zeroes,
    )

    const initProposal = grouped[defaultProposalTypes.external_init].at(0)!

    const externalKeyPair = await cs.hpke.deriveKeyPair(state.keySchedule.externalSecret)

    const externalInitSecret = await importSecret(
      await cs.hpke.exportPrivateKey(externalKeyPair.privateKey),
      initProposal.proposal.externalInit.kemOutput,
      cs,
    )

    return {
      needsUpdatePath: true,
      tree: treeAfterRemove,
      pskSecret: updatedPskSecret,
      pskIds,
      additionalResult: {
        kind: "externalCommit",
        externalInitSecret,
        newMemberLeafIndex: nodeToLeafIndex(findBlankLeafNodeIndexOrExtend(treeAfterRemove)),
      },
      selfRemoved: false,
      allProposals,
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
export async function joinGroup(
  welcome: Welcome,
  keyPackage: KeyPackage,
  privateKeys: PrivateKeyPackage,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
  ratchetTree?: RatchetTree,
  resumingFromState?: ClientState,
  clientConfig: ClientConfig = defaultClientConfig,
): Promise<ClientState> {
  const res = await joinGroupWithExtensions(
    welcome,
    keyPackage,
    privateKeys,
    pskSearch,
    cs,
    ratchetTree,
    resumingFromState,
    clientConfig,
  )

  return res[0]
}

/** @public */
export async function joinGroupWithExtensions(
  welcome: Welcome,
  keyPackage: KeyPackage,
  privateKeys: PrivateKeyPackage,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
  ratchetTree?: RatchetTree,
  resumingFromState?: ClientState,
  clientConfig: ClientConfig = defaultClientConfig,
): Promise<[ClientState, Extension[]]> {
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

  const credentialVerified = await clientConfig.authService.validateCredential(
    signerNode.leaf.credential,
    signerNode.leaf.signaturePublicKey,
  )

  if (!credentialVerified) throw new ValidationError("Could not validate credential")

  const groupInfoSignatureVerified = await verifyGroupInfoSignature(
    gi,
    signerNode.leaf.signaturePublicKey,
    cs.signature,
  )

  if (!groupInfoSignatureVerified) throw new CryptoVerificationError("Could not verify groupInfo signature")

  if (gi.groupContext.cipherSuite !== keyPackage.cipherSuite)
    throw new ValidationError("cipher suite in the GroupInfo does not match the cipher_suite in the KeyPackage")

  throwIfDefined(
    await validateRatchetTree(
      tree,
      gi.groupContext,
      clientConfig.lifetimeConfig,
      clientConfig.authService,
      gi.groupContext.treeHash,
      cs,
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

  return [
    {
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
      clientConfig,
    },
    gi.extensions,
  ]
}

/** @public */
export async function createGroup(
  groupId: Uint8Array,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  extensions: Extension[],
  cs: CiphersuiteImpl,
  clientConfig: ClientConfig = defaultClientConfig,
): Promise<ClientState> {
  const ratchetTree: RatchetTree = [{ nodeType: nodeTypes.leaf, leaf: keyPackage.leafNode }]

  const privatePath: PrivateKeyPath = {
    leafIndex: 0,
    privateKeys: { [0]: privateKeyPackage.hpkePrivateKey },
  }

  const confirmedTranscriptHash = new Uint8Array()

  const groupContext: GroupContext = {
    version: protocolVersions.mls10,
    cipherSuite: cs.name,
    epoch: 0n,
    treeHash: await treeHashRoot(ratchetTree, cs.hash),
    groupId,
    extensions,
    confirmedTranscriptHash,
  }

  throwIfDefined(await validateExternalSenders(extensions, clientConfig.authService))

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
    clientConfig,
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
  ratchetTree: RatchetTree,
  grouped: Proposals,
  gc: GroupContext,
  sentByClient: boolean,
  authService: AuthenticationService,
  lifetimeConfig: LifetimeConfig,
  s: Signature,
): Promise<[RatchetTree, [LeafIndex, KeyPackage][]]> {
  const treeAfterUpdate = await grouped[defaultProposalTypes.update].reduce(
    async (acc, { senderLeafIndex, proposal }) => {
      if (senderLeafIndex === undefined) throw new InternalError("No sender index found for update proposal")

      throwIfDefined(
        await validateLeafNodeUpdateOrCommit(proposal.update.leafNode, senderLeafIndex, gc, authService, s),
      )
      throwIfDefined(
        await validateLeafNodeCredentialAndKeyUniqueness(ratchetTree, proposal.update.leafNode, senderLeafIndex),
      )

      return updateLeafNode(await acc, proposal.update.leafNode, toLeafIndex(senderLeafIndex))
    },
    Promise.resolve(ratchetTree),
  )

  const treeAfterRemove = grouped[defaultProposalTypes.remove].reduce((acc, { proposal }) => {
    throwIfDefined(validateRemove(proposal.remove, ratchetTree))

    return removeLeafNode(acc, toLeafIndex(proposal.remove.removed))
  }, treeAfterUpdate)

  const [treeAfterAdd, addedLeafNodes] = await grouped[defaultProposalTypes.add].reduce(
    async (acc, { proposal }) => {
      throwIfDefined(
        await validateKeyPackage(
          proposal.add.keyPackage,
          gc,
          ratchetTree,
          sentByClient,
          lifetimeConfig,
          authService,
          s,
        ),
      )

      const [tree, ws] = await acc
      const [updatedTree, leafNodeIndex] = addLeafNode(tree, proposal.add.keyPackage.leafNode)
      return [
        updatedTree,
        [...ws, [nodeToLeafIndex(leafNodeIndex), proposal.add.keyPackage] as [LeafIndex, KeyPackage]],
      ]
    },
    Promise.resolve([treeAfterRemove, []] as [RatchetTree, [LeafIndex, KeyPackage][]]),
  )

  return [treeAfterAdd, addedLeafNodes]
}

export async function processProposal(
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

export function addHistoricalReceiverData(state: ClientState): [Map<bigint, EpochReceiverData>, Uint8Array[]] {
  const withNew = addToMap(state.historicalReceiverData, state.groupContext.epoch, {
    secretTree: state.secretTree,
    ratchetTree: state.ratchetTree,
    senderDataSecret: state.keySchedule.senderDataSecret,
    groupContext: state.groupContext,
    resumptionPsk: state.keySchedule.resumptionPsk,
  })

  const epochs = [...withNew.keys()]

  const result: [Map<bigint, EpochReceiverData>, Uint8Array[]] =
    epochs.length >= state.clientConfig.keyRetentionConfig.retainKeysForEpochs
      ? removeOldHistoricalReceiverData(withNew, state.clientConfig.keyRetentionConfig.retainKeysForEpochs)
      : [withNew, []]

  return result
}

function removeOldHistoricalReceiverData(
  historicalReceiverData: Map<bigint, EpochReceiverData>,
  max: number,
): [Map<bigint, EpochReceiverData>, Uint8Array[]] {
  const sortedEpochs = [...historicalReceiverData.keys()].sort((a, b) => (a < b ? -1 : 1))

  const cutoff = sortedEpochs.length - max

  const toBeDeleted = new Array<Uint8Array>()

  const map = new Map<bigint, EpochReceiverData>()
  for (const [n, epoch] of sortedEpochs.entries()) {
    const data = historicalReceiverData.get(epoch)!
    if (n < cutoff) {
      toBeDeleted.push(...allSecretTreeValues(data.secretTree))
    } else {
      map.set(epoch, data)
    }
  }

  return [new Map(sortedEpochs.slice(-max).map((epoch) => [epoch, historicalReceiverData.get(epoch)!])), []]
}
