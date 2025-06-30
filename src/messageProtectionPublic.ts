import {
  AuthenticatedContent,
  AuthenticatedContentProposalOrCommit,
  AuthenticatedContentTBM,
  createMembershipTag,
  verifyMembershipTag,
} from "./authenticatedContent"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import {
  FramedContent,
  signFramedContentApplicationOrProposal,
  toTbs,
  verifyFramedContentSignature,
} from "./framedContent"
import { GroupContext } from "./groupContext"
import { CryptoVerificationError, UsageError } from "./mlsError"
import { Proposal } from "./proposal"
import { findSignaturePublicKey, PublicMessage } from "./publicMessage"
import { RatchetTree } from "./ratchetTree"

export type ProtectProposalPublicResult = { publicMessage: PublicMessage }

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
    sender: { senderType: "member", leafIndex },
    contentType: "proposal",
    authenticatedData,
    proposal,
  }

  const tbs = {
    protocolVersion: groupContext.version,
    wireformat: "mls_public_message",
    content: framedContent,
    senderType: "member",
    context: groupContext,
  } as const

  const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)

  const authenticatedContent: AuthenticatedContent = {
    wireformat: "mls_public_message",
    content: framedContent,
    auth,
  }

  const msg = await protectPublicMessage(membershipKey, groupContext, authenticatedContent, cs)

  return { publicMessage: msg }
}

export async function protectPublicMessage(
  membershipKey: Uint8Array,
  groupContext: GroupContext,
  content: AuthenticatedContent,
  cs: CiphersuiteImpl,
): Promise<PublicMessage> {
  if (content.content.contentType === "application") throw new UsageError("Can't make an application message public")

  if (content.content.sender.senderType == "member") {
    const authenticatedContent: AuthenticatedContentTBM = {
      contentTbs: toTbs(content.content, "mls_public_message", groupContext),
      auth: content.auth,
    }

    const tag = await createMembershipTag(membershipKey, authenticatedContent, cs.hash)
    return {
      content: content.content,
      auth: content.auth,
      senderType: "member",
      membershipTag: tag,
    }
  }

  return {
    content: content.content,
    auth: content.auth,
    senderType: content.content.sender.senderType,
  }
}

export type ProtectCommitPublicResult = { publicMessage: PublicMessage }

export async function unprotectPublicMessage(
  membershipKey: Uint8Array,
  groupContext: GroupContext,
  ratchetTree: RatchetTree,
  msg: PublicMessage,
  cs: CiphersuiteImpl,
  overrideSignatureKey?: Uint8Array,
): Promise<AuthenticatedContentProposalOrCommit> {
  if (msg.content.contentType === "application") throw new UsageError("Can't make an application message public")

  if (msg.senderType === "member") {
    const authenticatedContent: AuthenticatedContentTBM = {
      contentTbs: toTbs(msg.content, "mls_public_message", groupContext),
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
    "mls_public_message",
    msg.content,
    msg.auth,
    groupContext,
    cs.signature,
  )

  if (!signatureValid) throw new CryptoVerificationError("Signature invalid")

  return {
    wireformat: "mls_public_message",
    content: msg.content,
    auth: msg.auth,
  }
}
