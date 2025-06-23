import { AuthenticatedContent, makeProposalRef } from "./authenticatedContent"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import {
  FramedContent,
  FramedContentTBSApplicationOrProposal,
  signFramedContentApplicationOrProposal,
  signFramedContentCommit,
} from "./framedContent"
import { GroupContext } from "./groupContext"
import { Proposal } from "./proposal"
import { PrivateMessage, protect } from "./privateMessage"
import { protectPublicMessage, PublicMessage } from "./publicMessage"
import { SecretTree } from "./secretTree"
import { Commit } from "./commit"

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

export type ProtectProposalResult = { privateMessage: PrivateMessage; newSecretTree: SecretTree; proposalRef: string }

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

  // Generate proposal reference
  const authenticatedContent = {
    wireformat: "mls_private_message" as const,
    content,
    auth,
  }
  const ref = await makeProposalRef(authenticatedContent, cs.hash)
  const proposalRef = Buffer.from(ref).toString("base64")

  return { privateMessage: privateMessage.privateMessage, newSecretTree, proposalRef }
}

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

export type ProtectCommitPublicResult = { publicMessage: PublicMessage }

export async function protectCommitPublic(
  signKey: Uint8Array,
  membershipKey: Uint8Array,
  confirmationKey: Uint8Array,
  groupContext: GroupContext,
  authenticatedData: Uint8Array,
  commit: Commit,
  leafIndex: number,
  cs: CiphersuiteImpl,
): Promise<ProtectCommitPublicResult> {
  const framedContent: FramedContent = {
    groupId: groupContext.groupId,
    epoch: groupContext.epoch,
    sender: { senderType: "member", leafIndex },
    contentType: "commit",
    authenticatedData,
    commit,
  }

  const tbs = {
    protocolVersion: groupContext.version,
    wireformat: "mls_public_message",
    content: framedContent,
    senderType: "member",
    context: groupContext,
  } as const

  const auth = await signFramedContentCommit(signKey, confirmationKey, groupContext.confirmedTranscriptHash, tbs, cs)

  const authenticatedContent: AuthenticatedContent = {
    wireformat: "mls_public_message",
    content: framedContent,
    auth,
  }

  const msg = await protectPublicMessage(membershipKey, groupContext, authenticatedContent, cs)

  return { publicMessage: msg }
}
