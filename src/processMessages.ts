import { AuthenticatedContentCommit } from "./authenticatedContent"
import {
  ClientState,
  GroupActiveState,
  addHistoricalReceiverData,
  applyProposals,
  nextEpochContext,
  processProposal,
} from "./clientState"
import { applyUpdatePathSecret } from "./createCommit"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Kdf, deriveSecret } from "./crypto/kdf"
import { verifyConfirmationTag } from "./framedContent"
import { GroupContext } from "./groupContext"
import { initializeEpoch } from "./keySchedule"
import { unprotectPrivateMessage } from "./messageProtection"
import { unprotectPublicMessage } from "./messageProtectionPublic"
import { pathToRoot } from "./pathSecrets"
import { PrivateKeyPath, mergePrivateKeyPaths, toPrivateKeyPath } from "./privateKeyPath"
import { PrivateMessage } from "./privateMessage"
import { PskIndex } from "./pskIndex"
import { PublicMessage } from "./publicMessage"
import { findBlankLeafNodeIndex, RatchetTree, addLeafNode } from "./ratchetTree"
import { createSecretTree } from "./secretTree"
import { Sender } from "./sender"
import { treeHashRoot } from "./treeHash"
import { leafToNodeIndex, leafWidth, nodeToLeafIndex, root } from "./treemath"
import { UpdatePath, applyUpdatePath } from "./updatePath"
import { addToMap } from "./util/addToMap"
import { WireformatName } from "./wireformat"

export type ProcessPrivateMessageResult =
  | {
      kind: "newState"
      newState: ClientState
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
): Promise<ProcessPrivateMessageResult> {
  if (pm.epoch < state.groupContext.epoch) {
    const receiverData = state.historicalReceiverData.get(pm.epoch)

    if (receiverData !== undefined) {
      const result = await unprotectPrivateMessage(
        receiverData.senderDataSecret,
        pm,
        receiverData.secretTree,
        receiverData.ratchetTree,
        receiverData.groupContext,
        state.keyRetentionConfig.retainKeysForGenerations,
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
        throw new Error("Cannot process commit or proposal from former epoch")
      }
    } else {
      throw new Error("Cannot process message, epoch too old")
    }
  }

  const result = await unprotectPrivateMessage(
    state.keySchedule.senderDataSecret,
    pm,
    state.secretTree,
    state.ratchetTree,
    state.groupContext,
    state.keyRetentionConfig.retainKeysForGenerations,
    cs,
  )

  const newState = { ...state, secretTree: result.tree }

  if (result.content.content.contentType === "application") {
    return { kind: "applicationMessage", message: result.content.content.applicationData, newState }
  } else if (result.content.content.contentType === "commit") {
    return {
      kind: "newState",
      newState: await processCommit(
        newState,
        result.content as AuthenticatedContentCommit,
        "mls_private_message",
        pskSearch,
        cs,
      ), //todo solve with types
    }
  } else {
    return {
      kind: "newState",
      newState: await processProposal(newState, result.content, result.content.content.proposal, cs.hash),
    }
  }
}

export async function processPublicMessage(
  state: ClientState,
  pm: PublicMessage,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
): Promise<ClientState> {
  if (pm.content.epoch < state.groupContext.epoch) throw new Error("Cannot process message, epoch too old")

  const content = await unprotectPublicMessage(
    state.keySchedule.membershipKey,
    state.groupContext,
    state.ratchetTree,
    pm,
    cs,
  )

  if (content === undefined) throw new Error("Could not unprotect private message")

  if (content.content.contentType === "proposal")
    return processProposal(state, content, content.content.proposal, cs.hash)
  else {
    return processCommit(state, content as AuthenticatedContentCommit, "mls_public_message", pskSearch, cs) //todo solve with types
  }
}

async function processCommit(
  state: ClientState,
  content: AuthenticatedContentCommit,
  wireformat: WireformatName,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
): Promise<ClientState> {
  if (content.content.epoch !== state.groupContext.epoch) throw new Error("Could not validate epoch")

  const senderLeafIndex = content.content.sender.senderType === "member" ? content.content.sender.leafIndex : undefined

  //TODO Verify that the proposals vector is valid according to the rules in Section 12.2.
  //TODO Verify that all PreSharedKey proposals in the proposals vector are available.
  const result = await applyProposals(state, content.content.commit.proposals, senderLeafIndex, pskSearch, cs)

  if (result.needsUpdatePath && content.content.commit.path === undefined) throw new Error("Update path is required")

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
      ? result.additionalResult.addedLeafNodes.map((l) => leafToNodeIndex(l[0]))
      : [findBlankLeafNodeIndex(result.tree) ?? result.tree.length + 1],
    cs.kdf,
  )

  const newTreeHash = await treeHashRoot(tree, cs.hash)

  if (content.auth.contentType !== "commit") throw new Error("Received content as commit, but not auth") //todo solve this with types?
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

  if (!confirmationTagValid) throw new Error("Could not verify confirmation tag")

  const secretTree = await createSecretTree(leafWidth(tree.length), epochSecrets.keySchedule.encryptionSecret, cs.kdf)

  const suspendedPendingReinit = result.additionalResult.kind === "reinit" ? result.additionalResult.reinit : undefined

  const groupActiveState: GroupActiveState = result.selfRemoved
    ? { kind: "removedFromGroup" }
    : suspendedPendingReinit !== undefined
      ? { kind: "suspendedPendingReinit", reinit: suspendedPendingReinit }
      : { kind: "active" }

  return {
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
  }
}

async function applyTreeUpdate(
  path: UpdatePath | undefined,
  sender: Sender,
  tree: RatchetTree,
  cs: CiphersuiteImpl,
  state: ClientState,
  groupContext: GroupContext,
  excludeNodes: number[],
  kdf: Kdf,
): Promise<[PrivateKeyPath, Uint8Array, RatchetTree]> {
  if (path === undefined) return [state.privatePath, new Uint8Array(kdf.size), tree] as const
  if (sender.senderType === "member") {
    const updatedTree = await applyUpdatePath(tree, sender.leafIndex, path, cs.hash)

    const [pkp, commitSecret] = await updatePrivateKeyPath(
      updatedTree,
      state,
      sender.leafIndex,
      { ...groupContext, treeHash: await treeHashRoot(updatedTree, cs.hash), epoch: groupContext.epoch + 1n },
      path,
      excludeNodes,
      cs,
    )
    return [pkp, commitSecret, updatedTree] as const
  } else {
    const [treeWithLeafNode, leafNodeIndex] = addLeafNode(tree, path.leafNode)

    const senderLeafIndex = nodeToLeafIndex(leafNodeIndex)
    const updatedTree = await applyUpdatePath(treeWithLeafNode, senderLeafIndex, path, cs.hash)

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
  leafNodeIndex: number,
  groupContext: GroupContext,
  path: UpdatePath,
  excludeNodes: number[],
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
  const pathSecrets = await pathToRoot(tree, secret.nodeIndex, secret.pathSecret, cs.kdf)
  const newPkp = mergePrivateKeyPaths(
    state.privatePath,
    await toPrivateKeyPath(pathSecrets, state.privatePath.leafIndex, cs),
  )

  const rootIndex = root(leafWidth(tree.length))
  const rootSecret = pathSecrets[rootIndex]
  if (rootSecret === undefined) throw new Error("Could not find secret for root")

  const commitSecret = await deriveSecret(rootSecret, "path", cs.kdf)
  return [newPkp, commitSecret] as const
}
