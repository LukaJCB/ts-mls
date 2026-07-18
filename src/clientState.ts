import { AuthenticatedContent, makeProposalRef } from "./authenticatedContent.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Hash } from "./crypto/hash.js"
import {
  ExtensionRequiredCapabilities,
  extensionsEqual,
  extensionsSupportedByCapabilities,
  GroupContextExtension,
  GroupInfoExtension,
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
import { PskId, pskTypes, resumptionPSKUsages } from "./presharedkey.js"

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
import { isDefaultProposal, Proposal, ProposalAdd, ProposalUpdate, Reinit } from "./proposal.js"
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
import { CryptoVerificationError, CodecError, InternalError, UsageError, ValidationError } from "./mlsError.js"

import { LeafNode } from "./leafNode.js"
import { nodeTypes } from "./nodeType.js"
import { protocolVersions } from "./protocolVersion.js"
import { firstCommonAncestor } from "./updatePath.js"
import { decryptGroupInfo, decryptGroupSecrets, Welcome } from "./welcome.js"
import { AuthenticationService } from "./authenticationService.js"
import { LifetimeConfig } from "./lifetimeConfig.js"
import { ClientConfig, defaultClientConfig } from "./clientConfig.js"
import { Encoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"

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
import {
  throwIfDefined,
  validateReinit,
  validateProposals,
  validateExternalInit,
  validateRatchetTree,
  validateExternalSenders,
  validateKeyPackage,
  validateLeafNodeCredentialAndKeyUniquenesss,
  validateLeafNodeUpdateOrCommit,
  NewLeafNodeWithSender,
} from "./validation.js"
import { emptyProposals, flattenExtensions, GroupedProposals } from "./groupedProposals.js"
import { SignatureKeyPair } from "./signatureKeyPair.js"
import { KeyPackageEqualityConfig } from "./keyPackageEqualityConfig.js"
import { defaultExtensionTypes } from "./defaultExtensionType.js"

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

export async function applyProposals(
  state: ClientState,
  mutableTree: RatchetTree,
  proposals: ProposalOrRef[],
  committerLeafIndex: LeafIndex | undefined,
  pskSearch: PskIndex,
  sentByClient: boolean,
  clientConfig: ClientConfig,
  authService: AuthenticationService,
  cs: CiphersuiteImpl,
): Promise<ApplyProposalsResult> {
  const allProposals = proposals.reduce((acc, cur) => {
    if (cur.proposalOrRefType === proposalOrRefTypes.proposal)
      return [...acc, { proposal: cur.proposal, senderLeafIndex: committerLeafIndex }]

    const p = state.unappliedProposals[bytesToBase64(cur.reference)]
    if (p === undefined) throw new ValidationError("Could not find proposal with supplied reference")
    return [...acc, p]
  }, [] as ProposalWithSender[])

  const grouped = groupProposals(allProposals)

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const isExternalInit = grouped[defaultProposalTypes.external_init].length > 0

  if (!isExternalInit) {
    if (grouped[defaultProposalTypes.reinit].length > 0) {
      const reinit = grouped[defaultProposalTypes.reinit].at(0)!.proposal.reinit

      throwIfDefined(validateReinit(allProposals, reinit, state.groupContext))

      return {
        pskSecret: zeroes,
        pskIds: [],
        needsUpdatePath: false,
        additionalResult: {
          kind: "reinit",
          reinit,
        },
        selfRemoved: false,
        allProposals,
        updatedLeaves: [],
        removedLeaves: [],
      }
    }

    throwIfDefined(
      await validateProposals(
        grouped,
        committerLeafIndex,
        state.groupContext,
        clientConfig.keyPackageEqualityConfig,
        clientConfig.lifetimeConfig,
        authService,
        sentByClient,
        mutableTree,
        cs,
      ),
    )

    const newExtensions = flattenExtensions(grouped[defaultProposalTypes.group_context_extensions])

    const addedLeafNodes = await applyTreeMutations(mutableTree, grouped)

    const [updatedPskSecret, pskIds] = await accumulatePskSecret(
      grouped[defaultProposalTypes.psk].map((p) => p.proposal.psk.preSharedKeyId),
      pskSearch,
      cs,
      zeroes,
    )

    const selfRemoved = mutableTree[leafToNodeIndex(toLeafIndex(state.privatePath.leafIndex))] === undefined

    const needsUpdatePath =
      allProposals.length === 0 ||
      allProposals.some(({ proposal }) => {
        const t = proposal.proposalType
        return t !== defaultProposalTypes.add && t !== defaultProposalTypes.psk && t !== defaultProposalTypes.reinit
      })

    const updatedLeaves: LeafIndex[] = [
      ...grouped[defaultProposalTypes.update].map(({ senderLeafIndex }) => senderLeafIndex),
      ...addedLeafNodes.map(([leafIndex]) => leafIndex),
    ]
    const removedLeaves: LeafIndex[] = grouped[defaultProposalTypes.remove].map(({ proposal }) =>
      toLeafIndex(proposal.remove.removed),
    )

    return {
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
      updatedLeaves,
      removedLeaves,
    }
  } else {
    throwIfDefined(validateExternalInit(grouped))

    grouped[defaultProposalTypes.remove].forEach(({ proposal }) => {
      removeLeafNodeMutable(mutableTree, toLeafIndex(proposal.remove.removed))
    })

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

    const removedLeaves: LeafIndex[] = grouped[defaultProposalTypes.remove].map(({ proposal }) =>
      toLeafIndex(proposal.remove.removed),
    )

    return {
      needsUpdatePath: true,
      pskSecret: updatedPskSecret,
      pskIds,
      additionalResult: {
        kind: "externalCommit",
        externalInitSecret,
        newMemberLeafIndex: nodeToLeafIndex(findBlankLeafNodeIndexOrExtend(mutableTree)),
      },
      selfRemoved: false,
      allProposals,
      updatedLeaves: [],
      removedLeaves,
    }
  }
}

function groupProposals(allProposals: ProposalWithSender[]): GroupedProposals {
  return allProposals.reduce((acc, cur) => {
    //this skips any custom proposals
    if (isDefaultProposal(cur.proposal)) {
      const proposalType = cur.proposal.proposalType
      const proposals = acc[proposalType] ?? []
      //todo shouldn't this return an error?
      return { ...acc, [cur.proposal.proposalType]: [...proposals, cur] }
    } else {
      return acc
    }
  }, emptyProposals)
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

  if (!credentialVerified) throw new ValidationError("Could not validate credential")

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
  grouped: GroupedProposals,
): Promise<[LeafIndex, KeyPackage][]> {
  for (const { senderLeafIndex, proposal } of grouped[defaultProposalTypes.update]) {
    if (senderLeafIndex === undefined) throw new InternalError("No sender index found for update proposal")

    const leafIndex = toLeafIndex(senderLeafIndex)
    updateLeafNodeMutable(mutableTree, proposal.update.leafNode, leafToNodeIndex(leafIndex))
  }

  grouped[defaultProposalTypes.remove].forEach(({ proposal }) => {
    removeLeafNodeMutable(mutableTree, toLeafIndex(proposal.remove.removed))
  })

  const addedLNs = new Array<[LeafIndex, KeyPackage]>(grouped[defaultProposalTypes.add].length)

  for (const [index, { proposal }] of grouped[defaultProposalTypes.add].entries()) {
    const leafNodeIndex = addLeafNodeMutable(mutableTree, proposal.add.keyPackage.leafNode)
    addedLNs[index] = [nodeToLeafIndex(leafNodeIndex), proposal.add.keyPackage]
  }

  return addedLNs
}

export async function processProposal(
  state: ClientState,
  content: AuthenticatedContent,
  proposal: Proposal,
  senderLeafIndex: LeafIndex | undefined,
  lifetimeConfig: LifetimeConfig,
  equalityConfig: KeyPackageEqualityConfig,
  authService: AuthenticationService,
  impl: CiphersuiteImpl,
): Promise<ClientState> {
  //Whenever a new credential is introduced in the group, it MUST be validated with the AS. In particular, at the following events in the protocol:
  //When a member receives an Add proposal adding a member to the group
  if (isDefaultProposal(proposal)) {
    switch (proposal.proposalType) {
      case defaultProposalTypes.add:
        await validateAddProposal(proposal, state, lifetimeConfig, equalityConfig, authService, impl)
        break
      case defaultProposalTypes.update:
        if (!senderLeafIndex) throw new ValidationError("Received an Update proposal from a non-member")
        await validateUpdateProposal(
          proposal,
          senderLeafIndex,
          equalityConfig,
          state.groupContext,
          state.ratchetTree,
          authService,
          impl,
        )
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
  lifetimeConfig: LifetimeConfig,
  keyPackageEqualityConfig: KeyPackageEqualityConfig,
  authService: AuthenticationService,
  impl: CiphersuiteImpl,
) {
  throwIfDefined(
    await validateKeyPackage(
      proposal.add.keyPackage,
      state.groupContext,
      false,
      lifetimeConfig,
      authService,
      impl.signature,
    ),
  )

  const withSender: NewLeafNodeWithSender = { kind: "add", keyPackage: proposal.add.keyPackage }
  const requiredCapabilities = state.groupContext.extensions.find(
    (e): e is ExtensionRequiredCapabilities => e.extensionType === defaultExtensionTypes.required_capabilities,
  )

  throwIfDefined(
    await validateLeafNodeCredentialAndKeyUniquenesss(
      state.ratchetTree,
      [withSender],
      keyPackageEqualityConfig,
      requiredCapabilities,
    ),
  )
}

/**
 * Validates an UpdateProposal that is not part of a commit
 */
async function validateUpdateProposal(
  proposal: ProposalUpdate,
  senderLeafIndex: LeafIndex,
  config: KeyPackageEqualityConfig,
  groupContext: GroupContext,
  tree: RatchetTree,
  authService: AuthenticationService,
  impl: CiphersuiteImpl,
) {
  const leafNodeIndex = leafToNodeIndex(senderLeafIndex)
  const oldLeafNode = tree[leafNodeIndex]
  if (oldLeafNode?.nodeType !== nodeTypes.leaf) throw new InternalError("Tried to update a non-leaf node")

  throwIfDefined(
    await validateLeafNodeUpdateOrCommit(
      proposal.update.leafNode,
      senderLeafIndex,
      oldLeafNode.leaf,
      groupContext,
      authService,
      impl.signature,
    ),
  )

  const withSender: NewLeafNodeWithSender = { kind: "update", leafNode: proposal.update.leafNode, senderLeafIndex }
  const requiredCapabilities = groupContext.extensions.find(
    (e): e is ExtensionRequiredCapabilities => e.extensionType === defaultExtensionTypes.required_capabilities,
  )

  throwIfDefined(await validateLeafNodeCredentialAndKeyUniquenesss(tree, [withSender], config, requiredCapabilities))
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
