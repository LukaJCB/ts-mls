import {
  AuthenticatedContent,
  AuthenticatedContentProposalOrCommit,
  AuthenticatedContentTBM,
  createMembershipTag,
  verifyMembershipTag,
} from "./authenticatedContent"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { Commit } from "./commit"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Extension } from "./extension"
import { decodeExternalSender, ExternalSender } from "./externalSender"
import {
  decodeFramedContent,
  decodeFramedContentAuthData,
  encodeFramedContent,
  encodeFramedContentAuthData,
  FramedContent,
  FramedContentAuthData,
  FramedContentTBS,
  FramedContentTBSExternal,
  signFramedContent,
  signFramedContentCommit,
  toTbs,
  verifyFramedContentSignature,
} from "./framedContent"
import { GroupContext } from "./groupContext"
import { getSignaturePublicKeyFromLeafIndex, RatchetTree } from "./ratchetTree"
import { SenderTypeName } from "./sender"

type PublicMessageInfo = PublicMessageInfoMember | PublicMessageInfoMemberOther
type PublicMessageInfoMember = { senderType: "member"; membershipTag: Uint8Array }
type PublicMessageInfoMemberOther = { senderType: Exclude<SenderTypeName, "member"> }

export const encodePublicMessageInfo: Encoder<PublicMessageInfo> = (info) => {
  switch (info.senderType) {
    case "member":
      return encodeVarLenData(info.membershipTag)
    case "external":
    case "new_member_proposal":
    case "new_member_commit":
      return new Uint8Array()
  }
}

export function decodePublicMessageInfo(senderType: SenderTypeName): Decoder<PublicMessageInfo> {
  switch (senderType) {
    case "member":
      return mapDecoder(decodeVarLenData, (membershipTag) => ({
        senderType,
        membershipTag,
      }))
    case "external":
    case "new_member_proposal":
    case "new_member_commit":
      return succeedDecoder({ senderType })
  }
}

export type PublicMessage = { content: FramedContent; auth: FramedContentAuthData } & PublicMessageInfo
export type MemberPublicMessage = PublicMessage & PublicMessageInfoMember
export type ExternalPublicMessage = PublicMessage & PublicMessageInfoMemberOther

export const encodePublicMessage: Encoder<PublicMessage> = contramapEncoders(
  [encodeFramedContent, encodeFramedContentAuthData, encodePublicMessageInfo],
  (msg) => [msg.content, msg.auth, msg] as const,
)

export const decodePublicMessage: Decoder<PublicMessage> = flatMapDecoder(decodeFramedContent, (content) =>
  mapDecoders(
    [decodeFramedContentAuthData(content.contentType), decodePublicMessageInfo(content.sender.senderType)],
    (auth, info) => ({
      ...info,
      content,
      auth,
    }),
  ),
)

export async function createMemberPublicMessage(
  membershipKey: Uint8Array,
  content: AuthenticatedContentTBM,
  cs: CiphersuiteImpl,
): Promise<MemberPublicMessage> {
  const tag = await createMembershipTag(membershipKey, content, cs.hash)

  return {
    content: content.contentTbs.content,
    auth: content.auth,
    senderType: "member",
    membershipTag: tag,
  }
}

export async function protectCommitPublic(
  signKey: Uint8Array,
  membershipKey: Uint8Array,
  confirmationKey: Uint8Array,
  groupContext: GroupContext,
  authenticatedData: Uint8Array,
  commit: Commit,
  cs: CiphersuiteImpl,
  leafIndex: number,
): Promise<PublicMessage> {
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

  return protectPublicMessage(membershipKey, groupContext, authenticatedContent, cs)
}

export async function protectPublicMessage(
  membershipKey: Uint8Array,
  groupContext: GroupContext,
  content: AuthenticatedContent,
  cs: CiphersuiteImpl,
): Promise<PublicMessage> {
  if (content.content.contentType === "application") throw new Error("Can't make an application message public")

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

export async function unprotectPublicMessage(
  membershipKey: Uint8Array,
  groupContext: GroupContext,
  ratchetTree: RatchetTree,
  msg: PublicMessage,
  cs: CiphersuiteImpl,
  overrideSignatureKey?: Uint8Array,
): Promise<AuthenticatedContentProposalOrCommit> {
  if (msg.content.contentType === "application") throw new Error("Can't make an application message public")

  if (msg.senderType === "member") {
    const authenticatedContent: AuthenticatedContentTBM = {
      contentTbs: toTbs(msg.content, "mls_public_message", groupContext),
      auth: msg.auth,
    }

    if (!(await verifyMembershipTag(membershipKey, authenticatedContent, msg.membershipTag, cs.hash)))
      throw new Error("Could not verify membership")
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

  if (!signatureValid) throw new Error("Signature invalid")

  return {
    wireformat: "mls_public_message",
    content: msg.content,
    auth: msg.auth,
  }
}

function findSignaturePublicKey(
  ratchetTree: RatchetTree,
  groupContext: GroupContext,
  framedContent: FramedContent,
): Uint8Array {
  switch (framedContent.sender.senderType) {
    case "member":
      return getSignaturePublicKeyFromLeafIndex(ratchetTree, framedContent.sender.leafIndex)
    case "external":
      return senderFromExtension(groupContext.extensions, framedContent.sender.senderIndex)!.signaturePublicKey //todo error handling
    case "new_member_proposal":
      throw new Error("Not implemented yet")
    case "new_member_commit": {
      if (framedContent.contentType !== "commit")
        throw new Error("Received new_member_commit but contentType is not commit")

      if (framedContent.commit.path === undefined) throw new Error("Commit contains no update path")
      return framedContent.commit.path.leafNode.signaturePublicKey
    }
  }
}

export function senderFromExtension(extensions: Extension[], senderIndex: number): ExternalSender | undefined {
  const externalSenderExtensions = extensions.filter((ex) => ex.extensionType === "external_senders")

  const externalSenderExtension = externalSenderExtensions[senderIndex]

  if (externalSenderExtension !== undefined) {
    const externalSender = decodeExternalSender(externalSenderExtension.extensionData, 0)
    if (externalSender === undefined) throw new Error("Could not decode ExternalSender")

    return externalSender[0]
  }
}

export async function createPublicMessage(
  signKey: Uint8Array,
  confirmationKey: Uint8Array,
  confirmedTranscriptHash: Uint8Array,
  tbs: FramedContentTBSExternal,
  cs: CiphersuiteImpl,
): Promise<PublicMessage> {
  const auth = await signFramedContent(signKey, confirmationKey, confirmedTranscriptHash, tbs, cs)
  return { auth, content: tbs.content, senderType: tbs.senderType }
}

export async function createPublicMessageMember(
  signKey: Uint8Array,
  confirmationKey: Uint8Array,
  confirmedTranscriptHash: Uint8Array,
  membershipKey: Uint8Array,
  tbs: FramedContentTBS,
  cs: CiphersuiteImpl,
): Promise<MemberPublicMessage> {
  const auth = await signFramedContent(signKey, confirmationKey, confirmedTranscriptHash, tbs, cs)
  const tbm = { auth, contentTbs: tbs }

  const tag = await createMembershipTag(membershipKey, tbm, cs.hash)

  return { auth, content: tbs.content, senderType: "member", membershipTag: new Uint8Array(tag) }
}
