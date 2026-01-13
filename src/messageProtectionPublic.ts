import {
  AuthenticatedContent,
  AuthenticatedContentProposalOrCommit,
  AuthenticatedContentTBM,
  createMembershipTag,
  verifyMembershipTag,
} from "./authenticatedContent.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import {
  FramedContent,
  signFramedContentApplicationOrProposal,
  toTbs,
  verifyFramedContentSignature,
} from "./framedContent.js"
import { GroupContext } from "./groupContext.js"
import { CryptoVerificationError, UsageError } from "./mlsError.js"
import { Proposal } from "./proposal.js"
import { ExternalPublicMessage, findSignaturePublicKey, PublicMessage } from "./publicMessage.js"
import { RatchetTree } from "./ratchetTree.js"
import { senderTypes, SenderNonMember } from "./sender.js"
import { contentTypes } from "./contentType.js"
import { wireformats } from "./wireformat.js"

export interface ProtectProposalPublicResult {
  publicMessage: PublicMessage
}

export async function protectProposalPublic(
  signKey: Uint8Array,
  membershipKey: Uint8Array,
  groupContext: GroupContext,
  authenticatedData: Uint8Array,
  proposal: Proposal,
  leafIndex: number,
  cs: CiphersuiteImpl,
): Promise<ProtectProposalPublicResult> {
  const framedContent: FramedContent = {
    groupId: groupContext.groupId,
    epoch: groupContext.epoch,
    sender: { senderType: senderTypes.member, leafIndex },
    contentType: contentTypes.proposal,
    authenticatedData,
    proposal,
  }

  const tbs = {
    protocolVersion: groupContext.version,
    wireformat: wireformats.mls_public_message,
    content: framedContent,
    senderType: senderTypes.member,
    context: groupContext,
  } as const

  const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)

  const authenticatedContent: AuthenticatedContent = {
    wireformat: wireformats.mls_public_message,
    content: framedContent,
    auth,
  }

  const msg = await protectPublicMessage(membershipKey, groupContext, authenticatedContent, cs)

  return { publicMessage: msg }
}

export async function protectExternalProposalPublic(
  signKey: Uint8Array,
  groupContext: GroupContext,
  authenticatedData: Uint8Array,
  proposal: Proposal,
  sender: SenderNonMember,
  cs: CiphersuiteImpl,
): Promise<ProtectProposalPublicResult> {
  const framedContent: FramedContent = {
    groupId: groupContext.groupId,
    epoch: groupContext.epoch,
    sender,
    contentType: contentTypes.proposal,
    authenticatedData,
    proposal,
  }

  const tbs = {
    protocolVersion: groupContext.version,
    wireformat: wireformats.mls_public_message,
    content: framedContent,
    senderType: sender.senderType,
    context: groupContext,
  } as const

  const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)

  const msg: ExternalPublicMessage = {
    content: framedContent,
    auth,
    senderType: sender.senderType,
  }

  return { publicMessage: msg }
}

export async function protectPublicMessage(
  membershipKey: Uint8Array,
  groupContext: GroupContext,
  content: AuthenticatedContent,
  cs: CiphersuiteImpl,
): Promise<PublicMessage> {
  if (content.content.contentType === contentTypes.application)
    throw new UsageError("Can't make an application message public")

  if (content.content.sender.senderType === senderTypes.member) {
    const authenticatedContent: AuthenticatedContentTBM = {
      contentTbs: toTbs(content.content, wireformats.mls_public_message, groupContext),
      auth: content.auth,
    }

    const tag = await createMembershipTag(membershipKey, authenticatedContent, cs.hash)
    return {
      content: content.content,
      auth: content.auth,
      senderType: senderTypes.member,
      membershipTag: tag,
    }
  }

  return {
    content: content.content,
    auth: content.auth,
    senderType: content.content.sender.senderType,
  }
}

export async function unprotectPublicMessage(
  membershipKey: Uint8Array,
  groupContext: GroupContext,
  ratchetTree: RatchetTree,
  msg: PublicMessage,
  cs: CiphersuiteImpl,
  overrideSignatureKey?: Uint8Array,
): Promise<AuthenticatedContentProposalOrCommit> {
  if (msg.content.contentType === contentTypes.application)
    throw new UsageError("Can't make an application message public")

  if (msg.senderType === senderTypes.member) {
    const authenticatedContent: AuthenticatedContentTBM = {
      contentTbs: toTbs(msg.content, wireformats.mls_public_message, groupContext),
      auth: msg.auth,
    }

    if (!(await verifyMembershipTag(membershipKey, authenticatedContent, msg.membershipTag, cs.hash)))
      throw new CryptoVerificationError("Could not verify membership")
  }

  const signaturePublicKey =
    overrideSignatureKey !== undefined
      ? overrideSignatureKey
      : findSignaturePublicKey(ratchetTree, groupContext, msg.content)

  const signatureValid = await verifyFramedContentSignature(
    signaturePublicKey,
    wireformats.mls_public_message,
    msg.content,
    msg.auth,
    groupContext,
    cs.signature,
  )

  if (!signatureValid) throw new CryptoVerificationError("Signature invalid")

  return {
    wireformat: wireformats.mls_public_message,
    content: msg.content,
    auth: msg.auth,
  }
}
