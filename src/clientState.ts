import { AuthenticatedContent, makeProposalRef } from "./authenticatedContent"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Hash } from "./crypto/hash"
import { Extension, extensionsEqual, extensionsSupportedByCapabilities } from "./extension"
import { createConfirmationTag, FramedContentCommit } from "./framedContent"
import { GroupContext } from "./groupContext"
import { ratchetTreeFromExtension, verifyGroupInfoConfirmationTag, verifyGroupInfoSignature } from "./groupInfo"
import { KeyPackage, makeKeyPackageRef, PrivateKeyPackage, verifyKeyPackage } from "./keyPackage"
import { deriveKeySchedule, initializeKeySchedule, KeySchedule } from "./keySchedule"
import { encodePskId, PreSharedKeyID } from "./presharedkey"

import {
  addLeafNode,
  findBlankLeafNodeIndexOrExtend,
  findLeafIndex,
  getHpkePublicKey,
  removeLeafNode,
  updateLeafNode,
} from "./ratchetTree"
import { RatchetTree } from "./ratchetTree"
import { createSecretTree, SecretTree } from "./secretTree"
import { createConfirmedHash, createInterimHash } from "./transcriptHash"
import { treeHashRoot } from "./treeHash"
import {
  directPath,
  isLeaf,
  LeafIndex,
  leafToNodeIndex,
  leafWidth,
  nodeToLeafIndex,
  toLeafIndex,
  toNodeIndex,
} from "./treemath"
import { firstCommonAncestor } from "./updatePath"
import { bytesToBase64 } from "./util/byteArray"
import { constantTimeEqual } from "./util/constantTimeCompare"
import { decryptGroupInfo, decryptGroupSecrets, Welcome } from "./welcome"
import { WireformatName } from "./wireformat"
import { ProposalOrRef } from "./proposalOrRefType"
import {
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
} from "./proposal"
import { pathToRoot } from "./pathSecrets"
import { PrivateKeyPath, mergePrivateKeyPaths, toPrivateKeyPath } from "./privateKeyPath"
import { UnappliedProposals, addUnappliedProposal, ProposalWithSender } from "./unappliedProposals"
import { accumulatePskSecret, PskIndex } from "./pskIndex"
import { getSenderLeafNodeIndex } from "./sender"
import { addToMap } from "./util/addToMap"
import { CryptoVerificationError, CodecError, InternalError, UsageError, ValidationError, MlsError } from "./mlsError"
import { Signature } from "./crypto/signature"
import {
  LeafNode,
  LeafNodeCommit,
  LeafNodeKeyPackage,
  LeafNodeUpdate,
  verifyLeafNodeSignature,
  verifyLeafNodeSignatureKeyPackage,
} from "./leafNode"
import { protocolVersions } from "./protocolVersion"
import { decodeRequiredCapabilities, RequiredCapabilities } from "./requiredCapabilities"
import { Capabilities } from "./capabilities"
import { verifyParentHashes } from "./parentHash"
import { AuthenticationService } from "./authenticationService"
import { LifetimeConfig } from "./lifetimeConfig"
import { KeyPackageEqualityConfig } from "./keyPackageEqualityConfig"
import { ClientConfig, defaultClientConfig } from "./clientConfig"
import { decodeExternalSender } from "./externalSender"
import { arraysEqual } from "./util/array"

export interface ClientState {
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
  clientConfig: ClientConfig
}

export type GroupActiveState =
  | { kind: "active" }
  | { kind: "suspendedPendingReinit"; reinit: Reinit }
  | { kind: "removedFromGroup" }

/**
 * This type contains everything necessary to receieve application messages for an earlier epoch
 */
export interface EpochReceiverData {
  resumptionPsk: Uint8Array
  secretTree: SecretTree
  ratchetTree: RatchetTree
  senderDataSecret: Uint8Array
  groupContext: GroupContext
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
  add: { senderLeafIndex: number | undefined; proposal: ProposalAdd }[]
  update: { senderLeafIndex: number | undefined; proposal: ProposalUpdate }[]
  remove: { senderLeafIndex: number | undefined; proposal: ProposalRemove }[]
  psk: { senderLeafIndex: number | undefined; proposal: ProposalPSK }[]
  reinit: { senderLeafIndex: number | undefined; proposal: ProposalReinit }[]
  external_init: { senderLeafIndex: number | undefined; proposal: ProposalExternalInit }[]
  group_context_extensions: { senderLeafIndex: number | undefined; proposal: ProposalGroupContextExtensions }[]
}

const emptyProposals: Proposals = {
  add: [],
  update: [],
  remove: [],
  psk: [],
  reinit: [],
  external_init: [],
  group_context_extensions: [],
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
  const containsUpdateByCommitter = p.update.some(
    (o) => o.senderLeafIndex !== undefined && o.senderLeafIndex === committerLeafIndex,
  )

  if (containsUpdateByCommitter)
    return new ValidationError("Commit cannot contain an update proposal sent by committer")

  const containsRemoveOfCommitter = p.remove.some((o) => o.proposal.remove.removed === committerLeafIndex)

  if (containsRemoveOfCommitter)
    return new ValidationError("Commit cannot contain a remove proposal removing committer")

  const multipleUpdateRemoveForSameLeaf =
    p.update.some(
      ({ senderLeafIndex: a }, indexA) =>
        p.update.some(({ senderLeafIndex: b }, indexB) => a === b && indexA !== indexB) ||
        p.remove.some((r) => r.proposal.remove.removed === a),
    ) ||
    p.remove.some(
      (a, indexA) =>
        p.remove.some((b, indexB) => b.proposal.remove.removed === a.proposal.remove.removed && indexA !== indexB) ||
        p.update.some(({ senderLeafIndex }) => a.proposal.remove.removed === senderLeafIndex),
    )

  if (multipleUpdateRemoveForSameLeaf)
    return new ValidationError(
      "Commit cannot contain multiple update and/or remove proposals that apply to the same leaf",
    )

  const multipleAddsContainSameKeypackage = p.add.some(({ proposal: a }, indexA) =>
    p.add.some(
      ({ proposal: b }, indexB) => config.compareKeyPackages(a.add.keyPackage, b.add.keyPackage) && indexA !== indexB,
    ),
  )

  if (multipleAddsContainSameKeypackage)
    return new ValidationError(
      "Commit cannot contain multiple Add proposals that contain KeyPackages that represent the same client",
    )

  // checks if there is an Add proposal with a KeyPackage that matches a client already in the group
  // unless there is a Remove proposal in the list removing the matching client from the group.
  const addsContainExistingKeypackage = p.add.some(({ proposal }) =>
    tree.some(
      (node, nodeIndex) =>
        node !== undefined &&
        node.nodeType === "leaf" &&
        config.compareKeyPackageToLeafNode(proposal.add.keyPackage, node.leaf) &&
        p.remove.every((r) => r.proposal.remove.removed !== nodeToLeafIndex(toNodeIndex(nodeIndex))),
    ),
  )

  if (addsContainExistingKeypackage)
    return new ValidationError("Commit cannot contain an Add proposal for someone already in the group")

  const everyLeafSupportsGroupExtensions = p.add.every(({ proposal }) =>
    extensionsSupportedByCapabilities(groupContext.extensions, proposal.add.keyPackage.leafNode.capabilities),
  )

  if (!everyLeafSupportsGroupExtensions)
    return new ValidationError("Added leaf node that doesn't support extension in GroupContext")

  const multiplePskWithSamePskId = p.psk.some((a, indexA) =>
    p.psk.some(
      (b, indexB) =>
        constantTimeEqual(encodePskId(a.proposal.psk.preSharedKeyId), encodePskId(b.proposal.psk.preSharedKeyId)) &&
        indexA !== indexB,
    ),
  )

  if (multiplePskWithSamePskId)
    return new ValidationError("Commit cannot contain PreSharedKey proposals that reference the same PreSharedKeyID")

  const multipleGroupContextExtensions = p.group_context_extensions.length > 1

  if (multipleGroupContextExtensions)
    return new ValidationError("Commit cannot contain multiple GroupContextExtensions proposals")

  const allExtensions = flattenExtensions(p.group_context_extensions)

  const requiredCapabilities = allExtensions.find((e) => e.extensionType === "required_capabilities")

  if (requiredCapabilities !== undefined) {
    const caps = decodeRequiredCapabilities(requiredCapabilities.extensionData, 0)
    if (caps === undefined) return new CodecError("Could not decode required_capabilities")

    const everyLeafSupportsCapabilities = tree
      .filter((n) => n !== undefined && n.nodeType === "leaf")
      .every((l) => capabiltiesAreSupported(caps[0], l.leaf.capabilities))

    if (!everyLeafSupportsCapabilities) return new ValidationError("Not all members support required capabilities")

    const allAdditionsSupportCapabilities = p.add.every((a) =>
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
  const externalSenders = extensions.filter((e) => e.extensionType === "external_senders")
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
  const treeIsStructurallySound = tree.every((n, index) =>
    isLeaf(toNodeIndex(index)) ? n === undefined || n.nodeType === "leaf" : n === undefined || n.nodeType === "parent",
  )

  if (!treeIsStructurallySound) return new ValidationError("Received Ratchet Tree is not structurally sound")

  const parentHashesVerified = await verifyParentHashes(tree, cs.hash)

  if (!parentHashesVerified) return new CryptoVerificationError("Unable to verify parent hash")

  if (!constantTimeEqual(treeHash, await treeHashRoot(tree, cs.hash)))
    return new ValidationError("Unable to verify tree hash")

  //validate all parent nodes
  for (const [parentIndex, n] of tree.entries()) {
    if (n?.nodeType === "parent") {
      // verify unmerged leaves
      for (const unmergedLeaf of n.parent.unmergedLeaves) {
        const leafIndex = toLeafIndex(unmergedLeaf)
        const dp = directPath(leafToNodeIndex(leafIndex), leafWidth(tree.length))
        const nodeIndex = leafToNodeIndex(leafIndex)
        if (tree[nodeIndex]?.nodeType !== "leaf" && !dp.includes(toNodeIndex(parentIndex)))
          return new ValidationError("Unmerged leaf did not represent a non-blank descendant leaf node")

        for (const parentIdx of dp) {
          const dpNode = tree[parentIdx]

          if (dpNode !== undefined) {
            if (dpNode.nodeType !== "parent") return new InternalError("Expected parent node")

            if (!arraysEqual(dpNode.parent.unmergedLeaves, n.parent.unmergedLeaves))
              return new ValidationError("non-blank intermediate node must list leaf node in its unmerged_leaves")
          }
        }
      }
    }
  }

  const duplicateHpkeKeys = hasDuplicateUint8Arrays(
    tree.map((n) => (n !== undefined ? getHpkePublicKey(n) : undefined)),
  )

  if (duplicateHpkeKeys) return new ValidationError("Multiple public keys with the same value")

  // validate all leaf nodes
  for (const [index, n] of tree.entries()) {
    if (n?.nodeType === "leaf") {
      const err =
        n.leaf.leafNodeSource === "key_package"
          ? await validateLeafNodeKeyPackage(
              n.leaf,
              groupContext,
              tree,
              false,
              config,
              authService,
              nodeToLeafIndex(toNodeIndex(index)),
              cs.signature,
            )
          : await validateLeafNodeUpdateOrCommit(
              n.leaf,
              nodeToLeafIndex(toNodeIndex(index)),
              groupContext,
              tree,
              authService,
              cs.signature,
            )

      if (err !== undefined) return err
    }
  }
}

function hasDuplicateUint8Arrays(byteArrays: (Uint8Array | undefined)[]): boolean {
  const seen = new Set<string>()

  for (const data of byteArrays) {
    if (data === undefined) continue

    const key = bytesToBase64(data)
    if (seen.has(key)) {
      return true
    }
    seen.add(key)
  }

  return false
}

export async function validateLeafNodeUpdateOrCommit(
  leafNode: LeafNodeCommit | LeafNodeUpdate,
  leafIndex: number,
  groupContext: GroupContext,
  tree: RatchetTree,
  authService: AuthenticationService,
  s: Signature,
): Promise<MlsError | undefined> {
  const signatureValid = await verifyLeafNodeSignature(leafNode, groupContext.groupId, leafIndex, s)

  if (!signatureValid) return new CryptoVerificationError("Could not verify leaf node signature")

  const commonError = await validateLeafNodeCommon(leafNode, groupContext, tree, authService, leafIndex)

  if (commonError !== undefined) return commonError
}

export function throwIfDefined(err: MlsError | undefined): void {
  if (err !== undefined) throw err
}

async function validateLeafNodeCommon(
  leafNode: LeafNode,
  groupContext: GroupContext,
  tree: RatchetTree,
  authService: AuthenticationService,
  leafIndex?: number,
) {
  const credentialValid = await authService.validateCredential(leafNode.credential, leafNode.signaturePublicKey)

  if (!credentialValid) return new ValidationError("Could not validate credential")

  const requiredCapabilities = groupContext.extensions.find((e) => e.extensionType === "required_capabilities")

  if (requiredCapabilities !== undefined) {
    const caps = decodeRequiredCapabilities(requiredCapabilities.extensionData, 0)
    if (caps === undefined) return new CodecError("Could not decode required_capabilities")

    const leafSupportsCapabilities = capabiltiesAreSupported(caps[0], leafNode.capabilities)

    if (!leafSupportsCapabilities) return new ValidationError("LeafNode does not support required capabilities")
  }

  const credentialUnsupported = tree.some(
    (node) =>
      node !== undefined &&
      node.nodeType === "leaf" &&
      !node.leaf.capabilities.credentials.includes(leafNode.credential.credentialType),
  )

  if (credentialUnsupported)
    return new ValidationError("LeafNode has credential that is not supported by member of the group")

  const extensionsSupported = extensionsSupportedByCapabilities(leafNode.extensions, leafNode.capabilities)

  if (!extensionsSupported) return new ValidationError("LeafNode contains extension not listed in capabilities")

  const keysAreNotUnique = tree.some(
    (node, nodeIndex) =>
      node !== undefined &&
      node.nodeType === "leaf" &&
      (constantTimeEqual(node.leaf.hpkePublicKey, leafNode.hpkePublicKey) ||
        constantTimeEqual(node.leaf.signaturePublicKey, leafNode.signaturePublicKey)) &&
      leafIndex !== nodeToLeafIndex(toNodeIndex(nodeIndex)),
  )

  if (keysAreNotUnique) return new ValidationError("hpke and signature keys not unique")
}

async function validateLeafNodeKeyPackage(
  leafNode: LeafNodeKeyPackage,
  groupContext: GroupContext,
  tree: RatchetTree,
  sentByClient: boolean,
  config: LifetimeConfig,
  authService: AuthenticationService,
  leafIndex: number | undefined,
  s: Signature,
): Promise<MlsError | undefined> {
  const signatureValid = await verifyLeafNodeSignatureKeyPackage(leafNode, s)
  if (!signatureValid) return new CryptoVerificationError("Could not verify leaf node signature")

  //verify lifetime
  if (sentByClient || config.validateLifetimeOnReceive) {
    if (leafNode.leafNodeSource === "key_package") {
      const currentTime = BigInt(Math.floor(Date.now() / 1000))
      if (leafNode.lifetime.notBefore > currentTime || leafNode.lifetime.notAfter < currentTime)
        return new ValidationError("Current time not within Lifetime")
    }
  }

  const commonError = await validateLeafNodeCommon(leafNode, groupContext, tree, authService, leafIndex)

  if (commonError !== undefined) return commonError
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

  const leafNodeError = await validateLeafNodeKeyPackage(
    kp.leafNode,
    groupContext,
    tree,
    sentByClient,
    config,
    authService,
    undefined,
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

  if (protocolVersions[reinit.version] < protocolVersions[gc.version])
    return new ValidationError("A ReInit proposal cannot use a version less than the version for the current group")
}

function validateExternalInit(grouped: Proposals): ValidationError | undefined {
  if (grouped.external_init.length > 1)
    return new ValidationError("Cannot contain more than one external_init proposal")

  if (grouped.remove.length > 1) return new ValidationError("Cannot contain more than one remove proposal")

  if (
    grouped.add.length > 0 ||
    grouped.group_context_extensions.length > 0 ||
    grouped.reinit.length > 0 ||
    grouped.update.length > 0
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
    if (cur.proposalOrRefType === "proposal")
      return [...acc, { proposal: cur.proposal, senderLeafIndex: committerLeafIndex }]

    const p = state.unappliedProposals[bytesToBase64(cur.reference)]
    if (p === undefined) throw new ValidationError("Could not find proposal with supplied reference")
    return [...acc, p]
  }, [] as ProposalWithSender[])

  const grouped = allProposals.reduce((acc, cur) => {
    //this skips any custom proposals
    if (typeof cur.proposal.proposalType === "number") return acc
    const proposal = acc[cur.proposal.proposalType] ?? []
    return { ...acc, [cur.proposal.proposalType]: [...proposal, cur] }
  }, emptyProposals)

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const isExternalInit = grouped.external_init.length > 0

  if (!isExternalInit) {
    if (grouped.reinit.length > 0) {
      const reinit = grouped.reinit.at(0)!.proposal.reinit

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

    const newExtensions = flattenExtensions(grouped.group_context_extensions)

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
      grouped.psk.map((p) => p.proposal.psk.preSharedKeyId),
      pskSearch,
      cs,
      zeroes,
    )

    const selfRemoved = mutatedTree[leafToNodeIndex(toLeafIndex(state.privatePath.leafIndex))] === undefined

    const needsUpdatePath =
      allProposals.length === 0 || Object.values(grouped.update).length > 1 || Object.values(grouped.remove).length > 1

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

    const treeAfterRemove = grouped.remove.reduce((acc, { proposal }) => {
      return removeLeafNode(acc, toLeafIndex(proposal.remove.removed))
    }, state.ratchetTree)

    const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

    const [updatedPskSecret, pskIds] = await accumulatePskSecret(
      grouped.psk.map((p) => p.proposal.psk.preSharedKeyId),
      pskSearch,
      cs,
      zeroes,
    )

    const initProposal = grouped.external_init.at(0)!

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

export function makePskIndex(state: ClientState | undefined, externalPsks: Record<string, Uint8Array>): PskIndex {
  return {
    findPsk(preSharedKeyId) {
      if (preSharedKeyId.psktype === "external") {
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
  const newConfirmedHash = await createConfirmedHash(interimTranscriptHash, { wireformat, content, signature }, h)

  return {
    ...groupContext,
    epoch: groupContext.epoch + 1n,
    treeHash: updatedTreeHash,
    confirmedTranscriptHash: newConfirmedHash,
  }
}

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
  const keyPackageRef = await makeKeyPackageRef(keyPackage, cs.hash)
  const privKey = await cs.hpke.importPrivateKey(privateKeys.initPrivateKey)
  const groupSecrets = await decryptGroupSecrets(privKey, keyPackageRef, welcome, cs.hpke)

  if (groupSecrets === undefined) throw new CodecError("Could not decode group secrets")

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const [pskSecret, pskIds] = await accumulatePskSecret(groupSecrets.psks, pskSearch, cs, zeroes)

  const gi = await decryptGroupInfo(welcome, groupSecrets.joinerSecret, pskSecret, cs)
  if (gi === undefined) throw new CodecError("Could not decode group info")

  const resumptionPsk = pskIds.find((id) => id.psktype === "resumption")
  if (resumptionPsk !== undefined) {
    if (resumingFromState === undefined) throw new ValidationError("No prior state passed for resumption")

    if (resumptionPsk.pskEpoch !== resumingFromState.groupContext.epoch) throw new ValidationError("Epoch mismatch")

    if (!constantTimeEqual(resumptionPsk.pskGroupId, resumingFromState.groupContext.groupId))
      throw new ValidationError("old groupId mismatch")

    if (gi.groupContext.epoch !== 1n) throw new ValidationError("Resumption must be started at epoch 1")

    if (resumptionPsk.usage === "reinit") {
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
  if (signerNode.nodeType === "parent") throw new ValidationError("Expected non blank leaf node")

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

  const keySchedule = await deriveKeySchedule(groupSecrets.joinerSecret, pskSecret, gi.groupContext, cs.kdf)

  const confirmationTagVerified = await verifyGroupInfoConfirmationTag(gi, groupSecrets.joinerSecret, pskSecret, cs)

  if (!confirmationTagVerified) throw new CryptoVerificationError("Could not verify confirmation tag")

  const secretTree = await createSecretTree(leafWidth(tree.length), keySchedule.encryptionSecret, cs.kdf)

  return {
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
  }
}

export async function createGroup(
  groupId: Uint8Array,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  extensions: Extension[],
  cs: CiphersuiteImpl,
  clientConfig: ClientConfig = defaultClientConfig,
): Promise<ClientState> {
  const ratchetTree: RatchetTree = [{ nodeType: "leaf", leaf: keyPackage.leafNode }]

  const privatePath: PrivateKeyPath = {
    leafIndex: 0,
    privateKeys: { [0]: privateKeyPackage.hpkePrivateKey },
  }

  const confirmedTranscriptHash = new Uint8Array()

  const groupContext: GroupContext = {
    version: "mls10",
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

  const secretTree = await createSecretTree(1, keySchedule.encryptionSecret, cs.kdf)

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
  const treeAfterUpdate = await grouped.update.reduce(async (acc, { senderLeafIndex, proposal }) => {
    if (senderLeafIndex === undefined) throw new InternalError("No sender index found for update proposal")

    throwIfDefined(
      await validateLeafNodeUpdateOrCommit(proposal.update.leafNode, senderLeafIndex, gc, ratchetTree, authService, s),
    )
    return updateLeafNode(await acc, proposal.update.leafNode, toLeafIndex(senderLeafIndex))
  }, Promise.resolve(ratchetTree))

  const treeAfterRemove = grouped.remove.reduce((acc, { proposal }) => {
    throwIfDefined(validateRemove(proposal.remove, ratchetTree))

    return removeLeafNode(acc, toLeafIndex(proposal.remove.removed))
  }, treeAfterUpdate)

  const [treeAfterAdd, addedLeafNodes] = await grouped.add.reduce(
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

export function addHistoricalReceiverData(state: ClientState): Map<bigint, EpochReceiverData> {
  const withNew = addToMap(state.historicalReceiverData, state.groupContext.epoch, {
    secretTree: state.secretTree,
    ratchetTree: state.ratchetTree,
    senderDataSecret: state.keySchedule.senderDataSecret,
    groupContext: state.groupContext,
    resumptionPsk: state.keySchedule.resumptionPsk,
  })

  const epochs = [...withNew.keys()]

  const result =
    epochs.length >= state.clientConfig.keyRetentionConfig.retainKeysForEpochs
      ? removeOldHistoricalReceiverData(withNew, state.clientConfig.keyRetentionConfig.retainKeysForEpochs)
      : withNew

  return result
}

function removeOldHistoricalReceiverData(
  historicalReceiverData: Map<bigint, EpochReceiverData>,
  max: number,
): Map<bigint, EpochReceiverData> {
  const sortedEpochs = [...historicalReceiverData.keys()].sort((a, b) => (a < b ? -1 : 1))

  return new Map(sortedEpochs.slice(-max).map((epoch) => [epoch, historicalReceiverData.get(epoch)!]))
}
