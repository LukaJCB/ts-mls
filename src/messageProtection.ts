import { AuthenticatedContent, makeProposalRef } from "./authenticatedContent.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import {
  FramedContentTBSApplicationOrProposal,
  signFramedContentApplicationOrProposal,
  verifyFramedContentSignature,
} from "./framedContent.js"
import { GroupContext } from "./groupContext.js"
import { Proposal } from "./proposal.js"
import {
  decodePrivateMessageContent,
  decryptSenderData,
  encodePrivateMessageContent,
  encryptSenderData,
  PrivateContentAAD,
  privateContentAADEncoder,
  PrivateMessage,
  PrivateMessageContent,
  toAuthenticatedContent,
} from "./privateMessage.js"
import { consumeRatchet, ratchetToGeneration, SecretTree } from "./secretTree.js"
import { getSignaturePublicKeyFromLeafIndex, RatchetTree } from "./ratchetTree.js"
import { SenderData, SenderDataAAD } from "./sender.js"
import { leafToNodeIndex, toLeafIndex } from "./treemath.js"
import { KeyRetentionConfig } from "./keyRetentionConfig.js"
import { CryptoVerificationError, CodecError, ValidationError, MlsError } from "./mlsError.js"
import { PaddingConfig } from "./paddingConfig.js"
import { encode } from "./codec/tlsEncoder.js"

export interface ProtectApplicationDataResult {
  privateMessage: PrivateMessage
  newSecretTree: SecretTree
}

export async function protectApplicationData(
  signKey: Uint8Array,
  senderDataSecret: Uint8Array,
  applicationData: Uint8Array,
  authenticatedData: Uint8Array,
  groupContext: GroupContext,
  secretTree: SecretTree,
  leafIndex: number,
  paddingConfig: PaddingConfig,
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

  const result = await protect(
    senderDataSecret,
    authenticatedData,
    groupContext,
    secretTree,
    content,
    leafIndex,
    paddingConfig,
    cs,
  )

  return { newSecretTree: result.tree, privateMessage: result.privateMessage }
}

export interface ProtectProposalResult {
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
  paddingConfig: PaddingConfig,
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
    paddingConfig,
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

export interface ProtectResult {
  privateMessage: PrivateMessage
  tree: SecretTree
}

export async function protect(
  senderDataSecret: Uint8Array,
  authenticatedData: Uint8Array,
  groupContext: GroupContext,
  secretTree: SecretTree,
  content: PrivateMessageContent,
  leafIndex: number,
  config: PaddingConfig,
  cs: CiphersuiteImpl,
): Promise<{ privateMessage: PrivateMessage; tree: SecretTree }> {
  const { newTree, generation, reuseGuard, nonce, key } = await consumeRatchet(
    secretTree,
    toLeafIndex(leafIndex),
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
    encode(privateContentAADEncoder)(aad),
    encodePrivateMessageContent(config)(content),
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

export interface UnprotectResult {
  content: AuthenticatedContent
  tree: SecretTree
}

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

  const decrypted = await cs.hpke.decryptAead(key, nonce, encode(privateContentAADEncoder)(aad), msg.ciphertext)

  const pmc = decodePrivateMessageContent(msg.contentType)(decrypted, 0)?.[0]

  if (pmc === undefined) throw new CodecError("Could not decode PrivateMessageContent")

  const content = toAuthenticatedContent(pmc, msg, senderData.leafIndex)

  const signaturePublicKey =
    overrideSignatureKey !== undefined
      ? overrideSignatureKey
      : getSignaturePublicKeyFromLeafIndex(ratchetTree, toLeafIndex(senderData.leafIndex))

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
  if (tree[leafToNodeIndex(toLeafIndex(senderData.leafIndex))]?.nodeType !== "leaf")
    return new ValidationError("SenderData did not point to a non-blank leaf node")
}
