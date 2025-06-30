import { AuthenticatedContent, makeProposalRef } from "./authenticatedContent"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import {
  FramedContentTBSApplicationOrProposal,
  signFramedContentApplicationOrProposal,
  verifyFramedContentSignature,
} from "./framedContent"
import { GroupContext } from "./groupContext"
import { Proposal } from "./proposal"
import {
  decodePrivateMessageContent,
  decryptSenderData,
  encodePrivateContentAAD,
  encodePrivateMessageContent,
  encryptSenderData,
  PrivateContentAAD,
  PrivateMessage,
  PrivateMessageContent,
  toAuthenticatedContent,
} from "./privateMessage"
import { consumeRatchet, ratchetToGeneration, SecretTree } from "./secretTree"
import { getSignaturePublicKeyFromLeafIndex, RatchetTree } from "./ratchetTree"
import { SenderData, SenderDataAAD } from "./sender"
import { leafToNodeIndex } from "./treemath"
import { KeyRetentionConfig } from "./keyRetentionConfig"
import { CryptoVerificationError, CodecError, ValidationError, MlsError, InternalError } from "./mlsError"

export type ProtectApplicationDataResult = { privateMessage: PrivateMessage; newSecretTree: SecretTree }

export async function protectApplicationData(
  signKey: Uint8Array,
  senderDataSecret: Uint8Array,
  applicationData: Uint8Array,
  authenticatedData: Uint8Array,
  groupContext: GroupContext,
  secretTree: SecretTree,
  leafIndex: number,
  cs: CiphersuiteImpl,
): Promise<ProtectApplicationDataResult> {
  const tbs: FramedContentTBSApplicationOrProposal = {
    protocolVersion: groupContext.version,
    wireformat: "mls_private_message",
    content: {
      contentType: "application",
      applicationData,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender: {
        senderType: "member",
        leafIndex: leafIndex,
      },
      authenticatedData,
    },
    senderType: "member",
    context: groupContext,
  }

  const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)

  const content = {
    ...tbs.content,
    auth,
  }

  const result = await protect(senderDataSecret, authenticatedData, groupContext, secretTree, content, leafIndex, cs)

  return { newSecretTree: result.tree, privateMessage: result.privateMessage }
}

export type ProtectProposalResult = {
  privateMessage: PrivateMessage
  newSecretTree: SecretTree
  proposalRef: Uint8Array
}

export async function protectProposal(
  signKey: Uint8Array,
  senderDataSecret: Uint8Array,
  p: Proposal,
  authenticatedData: Uint8Array,
  groupContext: GroupContext,
  secretTree: SecretTree,
  leafIndex: number,
  cs: CiphersuiteImpl,
): Promise<ProtectProposalResult> {
  const tbs = {
    protocolVersion: groupContext.version,
    wireformat: "mls_private_message" as const,
    content: {
      contentType: "proposal" as const,
      proposal: p,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender: {
        senderType: "member" as const,
        leafIndex,
      },
      authenticatedData,
    },
    senderType: "member" as const,
    context: groupContext,
  }

  const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)
  const content = { ...tbs.content, auth }

  const privateMessage = await protect(
    senderDataSecret,
    authenticatedData,
    groupContext,
    secretTree,
    content,
    leafIndex,
    cs,
  )

  const newSecretTree = privateMessage.tree

  const authenticatedContent = {
    wireformat: "mls_private_message" as const,
    content,
    auth,
  }
  const proposalRef = await makeProposalRef(authenticatedContent, cs.hash)

  return { privateMessage: privateMessage.privateMessage, newSecretTree, proposalRef }
}

export type ProtectResult = { privateMessage: PrivateMessage; tree: SecretTree }

export async function protect(
  senderDataSecret: Uint8Array,
  authenticatedData: Uint8Array,
  groupContext: GroupContext,
  secretTree: SecretTree,
  content: PrivateMessageContent,
  leafIndex: number,
  cs: CiphersuiteImpl,
): Promise<{ privateMessage: PrivateMessage; tree: SecretTree }> {
  const node = secretTree[leafToNodeIndex(leafIndex)]
  if (node === undefined) throw new InternalError("Bad node index for secret tree")

  const { newTree, generation, reuseGuard, nonce, key } = await consumeRatchet(
    secretTree,
    leafToNodeIndex(leafIndex),
    content.contentType,
    cs,
  )

  const aad: PrivateContentAAD = {
    groupId: groupContext.groupId,
    epoch: groupContext.epoch,
    contentType: content.contentType,
    authenticatedData: authenticatedData,
  }

  const ciphertext = await cs.hpke.encryptAead(
    key,
    nonce,
    encodePrivateContentAAD(aad),
    encodePrivateMessageContent(content),
  )

  const senderData: SenderData = {
    leafIndex,
    generation,
    reuseGuard,
  }

  const senderAad: SenderDataAAD = {
    groupId: groupContext.groupId,
    epoch: groupContext.epoch,
    contentType: content.contentType,
  }

  const encryptedSenderData = await encryptSenderData(senderDataSecret, senderData, senderAad, ciphertext, cs)

  return {
    privateMessage: {
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      encryptedSenderData,
      contentType: content.contentType,
      authenticatedData,
      ciphertext,
    },
    tree: newTree,
  }
}

export type UnprotectResult = { content: AuthenticatedContent; tree: SecretTree }

export async function unprotectPrivateMessage(
  senderDataSecret: Uint8Array,
  msg: PrivateMessage,
  secretTree: SecretTree,
  ratchetTree: RatchetTree,
  groupContext: GroupContext,
  config: KeyRetentionConfig,
  cs: CiphersuiteImpl,
  overrideSignatureKey?: Uint8Array,
): Promise<UnprotectResult> {
  const senderData = await decryptSenderData(msg, senderDataSecret, cs)

  if (senderData === undefined) throw new CodecError("Could not decode senderdata")

  validateSenderData(senderData, ratchetTree)

  const { key, nonce, newTree } = await ratchetToGeneration(secretTree, senderData, msg.contentType, config, cs)

  const aad: PrivateContentAAD = {
    groupId: msg.groupId,
    epoch: msg.epoch,
    contentType: msg.contentType,
    authenticatedData: msg.authenticatedData,
  }

  const decrypted = await cs.hpke.decryptAead(key, nonce, encodePrivateContentAAD(aad), msg.ciphertext)

  const pmc = decodePrivateMessageContent(msg.contentType)(decrypted, 0)?.[0]

  if (pmc === undefined) throw new CodecError("Could not decode PrivateMessageContent")

  const content = toAuthenticatedContent(pmc, msg, senderData.leafIndex)

  const signaturePublicKey =
    overrideSignatureKey !== undefined
      ? overrideSignatureKey
      : getSignaturePublicKeyFromLeafIndex(ratchetTree, senderData.leafIndex)

  const signatureValid = await verifyFramedContentSignature(
    signaturePublicKey,
    "mls_private_message",
    content.content,
    content.auth,
    groupContext,
    cs.signature,
  )

  if (!signatureValid) throw new CryptoVerificationError("Signature invalid")

  return { tree: newTree, content }
}

export function validateSenderData(senderData: SenderData, tree: RatchetTree): MlsError | undefined {
  if (tree[leafToNodeIndex(senderData.leafIndex)]?.nodeType !== "leaf")
    return new ValidationError("SenderData did not point to a non-blank leaf node")
}
