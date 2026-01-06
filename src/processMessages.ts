import { AuthenticatedContentCommit } from "./authenticatedContent.js"
import {
  ClientState,
  addHistoricalReceiverData,
  applyProposals,
  nextEpochContext,
  processProposal,
  throwIfDefined,
  validateLeafNodeCredentialAndKeyUniqueness,
  validateLeafNodeUpdateOrCommit,
} from "./clientState.js"
import { GroupActiveState } from "./groupActiveState.js"
import { applyUpdatePathSecret } from "./createCommit.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Kdf, deriveSecret } from "./crypto/kdf.js"
import { verifyConfirmationTag } from "./framedContent.js"
import { GroupContext } from "./groupContext.js"
import { acceptAll, IncomingMessageAction, IncomingMessageCallback } from "./incomingMessageAction.js"
import { initializeEpoch } from "./keySchedule.js"
import { MlsPrivateMessage, MlsPublicMessage } from "./message.js"
import { unprotectPrivateMessage } from "./messageProtection.js"
import { unprotectPublicMessage } from "./messageProtectionPublic.js"
import { CryptoVerificationError, InternalError, ValidationError } from "./mlsError.js"
import { pathToRoot } from "./pathSecrets.js"
import { PrivateKeyPath, mergePrivateKeyPaths, toPrivateKeyPath } from "./privateKeyPath.js"
import { PrivateMessage } from "./privateMessage.js"
import { emptyPskIndex, PskIndex } from "./pskIndex.js"
import { PublicMessage } from "./publicMessage.js"
import { findBlankLeafNodeIndex, RatchetTree, addLeafNode } from "./ratchetTree.js"
import { createSecretTree } from "./secretTree.js"
import { getSenderLeafNodeIndex, Sender } from "./sender.js"
import { treeHashRoot } from "./treeHash.js"
import {
  LeafIndex,
  leafToNodeIndex,
  leafWidth,
  NodeIndex,
  nodeToLeafIndex,
  root,
  toLeafIndex,
  toNodeIndex,
} from "./treemath.js"
import { UpdatePath, applyUpdatePath } from "./updatePath.js"
import { addToMap } from "./util/addToMap.js"
import { WireformatName } from "./wireformat.js"

export type ProcessMessageResult =
  | {
      kind: "newState"
      newState: ClientState
      actionTaken: IncomingMessageAction
    }
  | { kind: "applicationMessage"; message: Uint8Array; newState: ClientState }

/**
 * Process private message and apply proposal or commit and return the updated ClientState or return an application message
 */
export async function processPrivateMessage(
  state: ClientState,
  pm: PrivateMessage,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
  callback: IncomingMessageCallback = acceptAll,
): Promise<ProcessMessageResult> {
  if (pm.epoch < state.groupContext.epoch) {
    const receiverData = state.historicalReceiverData.get(pm.epoch)

    if (receiverData !== undefined) {
      const result = await unprotectPrivateMessage(
        receiverData.senderDataSecret,
        pm,
        receiverData.secretTree,
        receiverData.ratchetTree,
        receiverData.groupContext,
        state.clientConfig.keyRetentionConfig,
        cs,
      )

      const newHistoricalReceiverData = addToMap(state.historicalReceiverData, pm.epoch, {
        ...receiverData,
        secretTree: result.tree,
      })

      const newState = { ...state, historicalReceiverData: newHistoricalReceiverData }

      if (result.content.content.contentType === "application") {
        return { kind: "applicationMessage", message: result.content.content.applicationData, newState }
      } else {
        throw new ValidationError("Cannot process commit or proposal from former epoch")
      }
    } else {
      throw new ValidationError("Cannot process message, epoch too old")
    }
  }

  const result = await unprotectPrivateMessage(
    state.keySchedule.senderDataSecret,
    pm,
    state.secretTree,
    state.ratchetTree,
    state.groupContext,
    state.clientConfig.keyRetentionConfig,
    cs,
  )

  const updatedState = { ...state, secretTree: result.tree }

  if (result.content.content.contentType === "application") {
    return { kind: "applicationMessage", message: result.content.content.applicationData, newState: updatedState }
  } else if (result.content.content.contentType === "commit") {
    const { newState, actionTaken } = await processCommit(
      updatedState,
      result.content as AuthenticatedContentCommit,
      "mls_private_message",
      pskSearch,
      callback,
      cs,
    ) //todo solve with types
    return {
      kind: "newState",
      newState,
      actionTaken,
    }
  } else {
    const action = callback({
      kind: "proposal",
      proposal: {
        proposal: result.content.content.proposal,
        senderLeafIndex: getSenderLeafNodeIndex(result.content.content.sender),
      },
    })
    if (action === "reject")
      return {
        kind: "newState",
        newState: updatedState,
        actionTaken: action,
      }
    else
      return {
        kind: "newState",
        newState: await processProposal(updatedState, result.content, result.content.content.proposal, cs.hash),
        actionTaken: action,
      }
  }
}

export interface NewStateWithActionTaken {
  newState: ClientState
  actionTaken: IncomingMessageAction
}

export async function processPublicMessage(
  state: ClientState,
  pm: PublicMessage,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
  callback: IncomingMessageCallback = acceptAll,
): Promise<NewStateWithActionTaken> {
  if (pm.content.epoch < state.groupContext.epoch) throw new ValidationError("Cannot process message, epoch too old")

  const content = await unprotectPublicMessage(
    state.keySchedule.membershipKey,
    state.groupContext,
    state.ratchetTree,
    pm,
    cs,
  )

  if (content.content.contentType === "proposal") {
    const action = callback({
      kind: "proposal",
      proposal: { proposal: content.content.proposal, senderLeafIndex: getSenderLeafNodeIndex(content.content.sender) },
    })
    if (action === "reject")
      return {
        newState: state,
        actionTaken: action,
      }
    else
      return {
        newState: await processProposal(state, content, content.content.proposal, cs.hash),
        actionTaken: action,
      }
  } else {
    return processCommit(state, content as AuthenticatedContentCommit, "mls_public_message", pskSearch, callback, cs) //todo solve with types
  }
}

async function processCommit(
  state: ClientState,
  content: AuthenticatedContentCommit,
  wireformat: WireformatName,
  pskSearch: PskIndex,
  callback: IncomingMessageCallback,
  cs: CiphersuiteImpl,
): Promise<NewStateWithActionTaken> {
  if (content.content.epoch !== state.groupContext.epoch) throw new ValidationError("Could not validate epoch")

  const senderLeafIndex =
    content.content.sender.senderType === "member" ? toLeafIndex(content.content.sender.leafIndex) : undefined

  const result = await applyProposals(state, content.content.commit.proposals, senderLeafIndex, pskSearch, false, cs)

  const action = callback({ kind: "commit", senderLeafIndex, proposals: result.allProposals })

  if (action === "reject") {
    return { newState: state, actionTaken: action }
  }

  if (content.content.commit.path !== undefined) {
    const committerLeafIndex =
      senderLeafIndex ??
      (result.additionalResult.kind === "externalCommit" ? result.additionalResult.newMemberLeafIndex : undefined)

    if (committerLeafIndex === undefined)
      throw new ValidationError("Cannot verify commit leaf node because no commiter leaf index found")

    throwIfDefined(
      await validateLeafNodeUpdateOrCommit(
        content.content.commit.path.leafNode,
        committerLeafIndex,
        state.groupContext,
        state.clientConfig.authService,
        cs.signature,
      ),
    )
    throwIfDefined(
      await validateLeafNodeCredentialAndKeyUniqueness(
        result.tree,
        content.content.commit.path.leafNode,
        committerLeafIndex,
      ),
    )
  }

  if (result.needsUpdatePath && content.content.commit.path === undefined)
    throw new ValidationError("Update path is required")

  const groupContextWithExtensions =
    result.additionalResult.kind === "memberCommit" && result.additionalResult.extensions.length > 0
      ? { ...state.groupContext, extensions: result.additionalResult.extensions }
      : state.groupContext

  const [pkp, commitSecret, tree] = await applyTreeUpdate(
    content.content.commit.path,
    content.content.sender,
    result.tree,
    cs,
    state,
    groupContextWithExtensions,
    result.additionalResult.kind === "memberCommit"
      ? result.additionalResult.addedLeafNodes.map((l) => leafToNodeIndex(toLeafIndex(l[0])))
      : [findBlankLeafNodeIndex(result.tree) ?? toNodeIndex(result.tree.length + 1)],
    cs.kdf,
  )

  const newTreeHash = await treeHashRoot(tree, cs.hash)

  if (content.auth.contentType !== "commit") throw new ValidationError("Received content as commit, but not auth") //todo solve this with types?
  const updatedGroupContext = await nextEpochContext(
    groupContextWithExtensions,
    wireformat,
    content.content,
    content.auth.signature,
    newTreeHash,
    state.confirmationTag,
    cs.hash,
  )

  const initSecret =
    result.additionalResult.kind === "externalCommit"
      ? result.additionalResult.externalInitSecret
      : state.keySchedule.initSecret

  const epochSecrets = await initializeEpoch(initSecret, commitSecret, updatedGroupContext, result.pskSecret, cs.kdf)

  const confirmationTagValid = await verifyConfirmationTag(
    epochSecrets.keySchedule.confirmationKey,
    content.auth.confirmationTag,
    updatedGroupContext.confirmedTranscriptHash,
    cs.hash,
  )

  if (!confirmationTagValid) throw new CryptoVerificationError("Could not verify confirmation tag")

  const secretTree = await createSecretTree(leafWidth(tree.length), epochSecrets.encryptionSecret, cs.kdf)

  const suspendedPendingReinit = result.additionalResult.kind === "reinit" ? result.additionalResult.reinit : undefined

  const groupActiveState: GroupActiveState = result.selfRemoved
    ? { kind: "removedFromGroup" }
    : suspendedPendingReinit !== undefined
      ? { kind: "suspendedPendingReinit", reinit: suspendedPendingReinit }
      : { kind: "active" }

  return {
    newState: {
      ...state,
      secretTree,
      ratchetTree: tree,
      privatePath: pkp,
      groupContext: updatedGroupContext,
      keySchedule: epochSecrets.keySchedule,
      confirmationTag: content.auth.confirmationTag,
      historicalReceiverData: addHistoricalReceiverData(state),
      unappliedProposals: {},
      groupActiveState,
    },
    actionTaken: action,
  }
}

async function applyTreeUpdate(
  path: UpdatePath | undefined,
  sender: Sender,
  tree: RatchetTree,
  cs: CiphersuiteImpl,
  state: ClientState,
  groupContext: GroupContext,
  excludeNodes: NodeIndex[],
  kdf: Kdf,
): Promise<[PrivateKeyPath, Uint8Array, RatchetTree]> {
  if (path === undefined) return [state.privatePath, new Uint8Array(kdf.size), tree] as const
  if (sender.senderType === "member") {
    const updatedTree = await applyUpdatePath(tree, toLeafIndex(sender.leafIndex), path, cs.hash)

    const [pkp, commitSecret] = await updatePrivateKeyPath(
      updatedTree,
      state,
      toLeafIndex(sender.leafIndex),
      { ...groupContext, treeHash: await treeHashRoot(updatedTree, cs.hash), epoch: groupContext.epoch + 1n },
      path,
      excludeNodes,
      cs,
    )
    return [pkp, commitSecret, updatedTree] as const
  } else {
    const [treeWithLeafNode, leafNodeIndex] = addLeafNode(tree, path.leafNode)

    const senderLeafIndex = nodeToLeafIndex(leafNodeIndex)
    const updatedTree = await applyUpdatePath(treeWithLeafNode, senderLeafIndex, path, cs.hash, true)

    const [pkp, commitSecret] = await updatePrivateKeyPath(
      updatedTree,
      state,
      senderLeafIndex,
      { ...groupContext, treeHash: await treeHashRoot(updatedTree, cs.hash), epoch: groupContext.epoch + 1n },
      path,
      excludeNodes,
      cs,
    )
    return [pkp, commitSecret, updatedTree] as const
  }
}

async function updatePrivateKeyPath(
  tree: RatchetTree,
  state: ClientState,
  leafNodeIndex: LeafIndex,
  groupContext: GroupContext,
  path: UpdatePath,
  excludeNodes: NodeIndex[],
  cs: CiphersuiteImpl,
): Promise<[PrivateKeyPath, Uint8Array]> {
  const secret = await applyUpdatePathSecret(
    tree,
    state.privatePath,
    leafNodeIndex,
    groupContext,
    path,
    excludeNodes,
    cs,
  )
  const pathSecrets = await pathToRoot(tree, toNodeIndex(secret.nodeIndex), secret.pathSecret, cs.kdf)
  const newPkp = mergePrivateKeyPaths(
    state.privatePath,
    await toPrivateKeyPath(pathSecrets, state.privatePath.leafIndex, cs),
  )

  const rootIndex = root(leafWidth(tree.length))
  const rootSecret = pathSecrets[rootIndex]
  if (rootSecret === undefined) throw new InternalError("Could not find secret for root")

  const commitSecret = await deriveSecret(rootSecret, "path", cs.kdf)
  return [newPkp, commitSecret] as const
}

export async function processMessage(
  message: MlsPrivateMessage | MlsPublicMessage,
  state: ClientState,
  pskIndex: PskIndex,
  action: IncomingMessageCallback,
  cs: CiphersuiteImpl,
): Promise<ProcessMessageResult> {
  if (message.wireformat === "mls_public_message") {
    const result = await processPublicMessage(state, message.publicMessage, pskIndex, cs, action)

    return { ...result, kind: "newState" }
  } else return processPrivateMessage(state, message.privateMessage, emptyPskIndex, cs, action)
}
