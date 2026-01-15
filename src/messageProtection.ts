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
  privateMessageContentDecoder,
  decryptSenderData,
  encryptSenderData,
  PrivateContentAAD,
  privateContentAADEncoder,
  privateMessageContentEncoder,
  PrivateMessage,
  PrivateMessageContent,
  toAuthenticatedContent,
} from "./privateMessage.js"
import { consumeRatchet, ratchetToGeneration, SecretTree } from "./secretTree.js"
import { getSignaturePublicKeyFromLeafIndex, RatchetTree } from "./ratchetTree.js"
import { senderTypes, SenderData, SenderDataAAD } from "./sender.js"
import { leafToNodeIndex, toLeafIndex } from "./treemath.js"
import { KeyRetentionConfig } from "./keyRetentionConfig.js"
import { CryptoVerificationError, CodecError, ValidationError, MlsError } from "./mlsError.js"
import { PaddingConfig } from "./paddingConfig.js"
import { encode } from "./codec/tlsEncoder.js"
import { nodeTypes } from "./nodeType.js"
import { contentTypes } from "./contentType.js"
import { wireformats } from "./wireformat.js"

export interface ProtectApplicationDataResult {
  privateMessage: PrivateMessage
  newSecretTree: SecretTree
  consumed: Uint8Array[]
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
    wireformat: wireformats.mls_private_message,
    content: {
      contentType: contentTypes.application,
      applicationData,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender: {
        senderType: senderTypes.member,
        leafIndex: leafIndex,
      },
      authenticatedData,
    },
    senderType: senderTypes.member,
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

  return { newSecretTree: result.tree, privateMessage: result.privateMessage, consumed: result.consumed }
}

export interface ProtectProposalResult {
  privateMessage: PrivateMessage
  newSecretTree: SecretTree
  proposalRef: Uint8Array
  consumed: Uint8Array[]
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
    wireformat: wireformats.mls_private_message,
    content: {
      contentType: contentTypes.proposal,
      proposal: p,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender: {
        senderType: senderTypes.member,
        leafIndex,
      },
      authenticatedData,
    },
    senderType: senderTypes.member,
    context: groupContext,
  }

  const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)
  const content = { ...tbs.content, auth }

  const protectResult = await protect(
    senderDataSecret,
    authenticatedData,
    groupContext,
    secretTree,
    content,
    leafIndex,
    paddingConfig,
    cs,
  )

  const newSecretTree = protectResult.tree

  const authenticatedContent = {
    wireformat: wireformats.mls_private_message,
    content,
    auth,
  }
  const proposalRef = await makeProposalRef(authenticatedContent, cs.hash)

  return { privateMessage: protectResult.privateMessage, newSecretTree, proposalRef, consumed: protectResult.consumed }
}

export interface ProtectResult {
  privateMessage: PrivateMessage
  tree: SecretTree
  consumed: Uint8Array[]
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
): Promise<ProtectResult> {
  const { newTree, generation, reuseGuard, nonce, key, consumed } = await consumeRatchet(
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
    encode(privateContentAADEncoder, aad),
    encode(privateMessageContentEncoder(config), content),
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
    consumed,
  }
}

export interface UnprotectResult {
  content: AuthenticatedContent
  tree: SecretTree
  consumed: Uint8Array[]
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

  const { key, nonce, newTree, consumed } = await ratchetToGeneration(
    secretTree,
    senderData,
    msg.contentType,
    config,
    cs,
  )

  const aad: PrivateContentAAD = {
    groupId: msg.groupId,
    epoch: msg.epoch,
    contentType: msg.contentType,
    authenticatedData: msg.authenticatedData,
  }

  const decrypted = await cs.hpke.decryptAead(key, nonce, encode(privateContentAADEncoder, aad), msg.ciphertext)

  const pmc = privateMessageContentDecoder(msg.contentType)(decrypted, 0)?.[0]

  if (pmc === undefined) throw new CodecError("Could not decode PrivateMessageContent")

  const content = toAuthenticatedContent(pmc, msg, senderData.leafIndex)

  const signaturePublicKey =
    overrideSignatureKey !== undefined
      ? overrideSignatureKey
      : getSignaturePublicKeyFromLeafIndex(ratchetTree, toLeafIndex(senderData.leafIndex))

  const signatureValid = await verifyFramedContentSignature(
    signaturePublicKey,
    wireformats.mls_private_message,
    content.content,
    content.auth,
    groupContext,
    cs.signature,
  )

  if (!signatureValid) throw new CryptoVerificationError("Signature invalid")

  return { tree: newTree, content, consumed }
}

export function validateSenderData(senderData: SenderData, tree: RatchetTree): MlsError | undefined {
  if (tree[leafToNodeIndex(toLeafIndex(senderData.leafIndex))]?.nodeType !== nodeTypes.leaf)
    return new ValidationError("SenderData did not point to a non-blank leaf node")
}
