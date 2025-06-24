import { AuthenticatedContent, makeProposalRef } from "./authenticatedContent"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Hash } from "./crypto/hash"
import { Extension, extensionsEqual } from "./extension"
import { createConfirmationTag, FramedContentCommit } from "./framedContent"
import { GroupContext } from "./groupContext"
import { ratchetTreeFromExtension, verifyGroupInfoConfirmationTag, verifyGroupInfoSignature } from "./groupInfo"
import { KeyPackage, makeKeyPackageRef, PrivateKeyPackage } from "./keyPackage"
import { deriveKeySchedule, initializeKeySchedule, KeySchedule } from "./keySchedule"
import { PreSharedKeyID, updatePskSecret } from "./presharedkey"

import { addLeafNode, findLeafIndex, removeLeafNode, updateLeafNode } from "./ratchetTree"
import { RatchetTree } from "./ratchetTree"
import { createSecretTree, SecretTree } from "./secretTree"
import { createConfirmedHash, createInterimHash } from "./transcriptHash"
import { treeHashRoot } from "./treeHash"
import { leafToNodeIndex, leafWidth, nodeToLeafIndex } from "./treemath"
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
} from "./proposal"
import { pathToRoot } from "./pathSecrets"
import { PrivateKeyPath, mergePrivateKeyPaths, toPrivateKeyPath } from "./privateKeyPath"
import { UnappliedProposals, addUnappliedProposal, ProposalWithSender } from "./unappliedProposals"
import { accumulatePskSecret, PskIndex } from "./pskIndex"
import { getSenderLeafNodeIndex } from "./sender"

export type ClientState = {
  groupContext: GroupContext
  keySchedule: KeySchedule
  secretTree: SecretTree
  ratchetTree: RatchetTree
  privatePath: PrivateKeyPath
  signaturePrivateKey: Uint8Array
  unappliedProposals: UnappliedProposals
  confirmationTag: Uint8Array
  historicalResumptionPsks: Map<bigint, Uint8Array>
  suspendedPendingReinit?: Reinit //todo expand this to include removedFromGroup?
}

export type Proposals = {
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

export type ApplyProposalsResult = {
  tree: RatchetTree
  pskSecret: Uint8Array
  pskIds: PreSharedKeyID[]
  needsUpdatePath: boolean
  additionalResult: ApplyProposalsData
}

type ApplyProposalsData =
  | { kind: "memberCommit"; addedLeafNodes: [number, KeyPackage][]; extensions: Extension[] }
  | { kind: "externalCommit"; externalInitSecret: Uint8Array }
  | { kind: "reinit"; reinit: Reinit }

function flattenExtensions(groupContextExtensions: { proposal: ProposalGroupContextExtensions }[]): Extension[] {
  return groupContextExtensions.reduce((acc, { proposal }) => {
    return [...acc, ...proposal.groupContextExtensions.extensions]
  }, [] as Extension[])
}

export async function applyProposals(
  state: ClientState,
  proposals: ProposalOrRef[],
  senderLeafIndex: number | undefined,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
): Promise<ApplyProposalsResult> {
  const allProposals = proposals.reduce((acc, cur) => {
    if (cur.proposalOrRefType === "proposal") return [...acc, { proposal: cur.proposal, senderLeafIndex }]

    const p = state.unappliedProposals[bytesToBase64(cur.reference)]
    if (p === undefined) throw new Error("Could not find proposal with supplied reference")
    return [...acc, p]
  }, [] as ProposalWithSender[])

  const grouped = allProposals.reduce((acc, cur) => {
    const proposal = acc[cur.proposal.proposalType] ?? []
    return { ...acc, [cur.proposal.proposalType]: [...proposal, cur] }
  }, emptyProposals)

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const isExternalInit = grouped.external_init.length > 0

  if (!isExternalInit) {
    if (grouped.reinit.length > 0) {
      if (allProposals.length !== 1) throw new Error("Reinit proposal needs to be commited by itself")

      const reinit = grouped.reinit.at(0)!.proposal.reinit

      return {
        tree: state.ratchetTree,
        pskSecret: zeroes,
        pskIds: [],
        needsUpdatePath: false,
        additionalResult: {
          kind: "reinit",
          reinit,
        },
      }
    }

    const newExtensions = flattenExtensions(grouped.group_context_extensions)

    const [mutatedTree, addedLeafNodes] = applyTreeMutations(state.ratchetTree, grouped)

    const [updatedPskSecret, pskIds] = await accumulatePskSecret(grouped.psk, pskSearch, cs, zeroes)

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
    }
  } else {
    if (grouped.external_init.length > 1) throw new Error("Cannot contain more than one external_init proposal")

    if (grouped.remove.length > 1) throw new Error("Cannot contain more than one remove proposal")

    if (
      grouped.add.length > 0 ||
      grouped.group_context_extensions.length > 0 ||
      grouped.reinit.length > 0 ||
      grouped.update.length > 0
    )
      throw new Error("Invalid proposals")

    const treeAfterRemove = grouped.remove.reduce((acc, { proposal }) => {
      return removeLeafNode(acc, proposal.remove.removed)
    }, state.ratchetTree)

    const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

    const [updatedPskSecret, pskIds] = await accumulatePskSecret(grouped.psk, pskSearch, cs, zeroes)

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
      additionalResult: { kind: "externalCommit", externalInitSecret },
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
        else return state.historicalResumptionPsks.get(preSharedKeyId.pskEpoch)
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
): Promise<ClientState> {
  const keyPackageRef = await makeKeyPackageRef(keyPackage, cs.hash)
  const privKey = await cs.hpke.importPrivateKey(privateKeys.initPrivateKey)
  const groupSecrets = await decryptGroupSecrets(privKey, keyPackageRef, welcome, cs.hpke)

  if (groupSecrets === undefined) throw new Error("Could not decrypt group secrets")

  const includesResumption = groupSecrets.psks.reduce((acc, cur) => {
    if (cur.psktype === "resumption" && (cur.usage === "branch" || cur.usage === "reinit")) {
      if (acc) throw new Error("Encountered multiple resumption PSKs")
      return true
    }
    return false
  }, false)

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const [pskSecret, pskIds] = await groupSecrets.psks.reduce(
    async (acc, cur, index) => {
      const [previousSecret, ids] = await acc
      const psk = pskSearch.findPsk(cur)

      if (psk === undefined) throw new Error("Could not find pskId referenced in proposal")

      const pskSecret = await updatePskSecret(previousSecret, cur, psk, index, groupSecrets.psks.length, cs)
      return [pskSecret, [...ids, cur]]
    },
    Promise.resolve([zeroes, [] as PreSharedKeyID[]] as const),
  )

  const gi = await decryptGroupInfo(welcome, groupSecrets.joinerSecret, pskSecret, cs)
  if (gi === undefined) throw new Error("Could not decrypt group info")

  const resumptionPsk = pskIds.find((id) => id.psktype === "resumption")
  if (resumptionPsk !== undefined) {
    if (resumingFromState === undefined) throw new Error("No prior state passed for resumption")

    if (resumptionPsk.pskEpoch !== resumingFromState.groupContext.epoch) throw new Error("Epoch mismatch")

    if (!constantTimeEqual(resumptionPsk.pskGroupId, resumingFromState.groupContext.groupId))
      throw new Error("old groupId mismatch")
    if (gi.groupContext.epoch !== 1n) throw new Error("Resumption must be started at epoch 1")

    if (resumptionPsk.usage === "reinit") {
      if (resumingFromState.suspendedPendingReinit === undefined)
        throw new Error("Found reinit psk but no old suspended clientState")

      if (!constantTimeEqual(resumingFromState.suspendedPendingReinit.groupId, gi.groupContext.groupId))
        throw new Error("new groupId mismatch")

      if (resumingFromState.suspendedPendingReinit.version !== gi.groupContext.version)
        throw new Error("Version mismatch")

      if (resumingFromState.suspendedPendingReinit.cipherSuite !== gi.groupContext.cipherSuite)
        throw new Error("Ciphersuite mismatch")

      if (!extensionsEqual(resumingFromState.suspendedPendingReinit.extensions, gi.groupContext.extensions))
        throw new Error("Extensions mismatch")
    }
  }

  const tree = ratchetTreeFromExtension(gi) ?? ratchetTree

  if (tree === undefined) throw new Error("No RatchetTree passed and no ratchet_tree extension")

  const signerNode = tree[leafToNodeIndex(gi.signer)]

  if (signerNode === undefined) {
    throw new Error("Undefined")
  }
  if (signerNode.nodeType === "parent") throw new Error("Expected non blank leaf node")

  const groupInfoSignatureVerified = verifyGroupInfoSignature(gi, signerNode.leaf.signaturePublicKey, cs.signature)

  if (!groupInfoSignatureVerified) throw new Error("Could not verify groupInfo signature")

  //todo more validation

  const newLeaf = findLeafIndex(tree, keyPackage.leafNode)

  if (newLeaf === undefined) throw new Error("Could not find own leaf when processing welcome")

  const privateKeyPath: PrivateKeyPath = {
    leafIndex: newLeaf,
    privateKeys: { [leafToNodeIndex(newLeaf)]: privateKeys.hpkePrivateKey },
  }

  const ancestorNodeIndex = firstCommonAncestor(tree, newLeaf, gi.signer)

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

  if (!confirmationTagVerified) throw new Error("Could not verify confirmation tag")

  const secretTree = await createSecretTree(leafWidth(tree.length), keySchedule.encryptionSecret, cs.kdf)

  const newGroupContext = { ...gi.groupContext }

  if (includesResumption) {
    //todo validate resumption
  }

  return {
    groupContext: newGroupContext,
    ratchetTree: tree,
    privatePath: updatedPkp,
    signaturePrivateKey: privateKeys.signaturePrivateKey,
    confirmationTag: gi.confirmationTag,
    unappliedProposals: {},
    keySchedule,
    secretTree,
    historicalResumptionPsks: new Map(),
  }
}

export async function createGroup(
  groupId: Uint8Array,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  extensions: Extension[],
  cs: CiphersuiteImpl,
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
    historicalResumptionPsks: new Map(),
    groupContext,
    confirmationTag,
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

function applyTreeMutations(tree: RatchetTree, grouped: Proposals): [RatchetTree, [number, KeyPackage][]] {
  const treeAfterUpdate = grouped.update.reduce((acc, { senderLeafIndex, proposal }) => {
    if (senderLeafIndex === undefined) throw new Error("No sender index found for update proposal")
    return updateLeafNode(acc, proposal.update.leafNode, senderLeafIndex)
  }, tree)

  const treeAfterRemove = grouped.remove.reduce((acc, { proposal }) => {
    return removeLeafNode(acc, proposal.remove.removed)
  }, treeAfterUpdate)

  const [treeAfterAdd, addedLeafNodes] = grouped.add.reduce(
    (acc, { proposal }) => {
      const [tree, ws] = acc
      const [updatedTree, leafNodeIndex] = addLeafNode(tree, proposal.add.keyPackage.leafNode)
      return [updatedTree, [...ws, [nodeToLeafIndex(leafNodeIndex), proposal.add.keyPackage] as [number, KeyPackage]]]
    },
    [treeAfterRemove, []] as [RatchetTree, [number, KeyPackage][]],
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
