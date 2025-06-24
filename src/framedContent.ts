import { decodeUint64, encodeUint64 } from "./codec/number"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { Commit, decodeCommit, encodeCommit } from "./commit"
import { ContentTypeName, decodeContentType, encodeContentType } from "./contentType"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Hash } from "./crypto/hash"
import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature"
import { decodeGroupContext, encodeGroupContext, GroupContext } from "./groupContext"
import { decodeWireformat, encodeWireformat, WireformatName } from "./wireformat"
import { decodeProposal, encodeProposal, Proposal } from "./proposal"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion"
import {
  decodeSender,
  decodeSenderType,
  encodeSender,
  Sender,
  SenderExternal,
  SenderMember,
  SenderNewMemberCommit,
  SenderNewMemberProposal,
} from "./sender"

export type FramedContentInfo = FramedContentApplicationData | FramedContentProposalData | FramedContentCommitData

export type FramedContentApplicationData = { contentType: "application"; applicationData: Uint8Array }
export type FramedContentProposalData = { contentType: "proposal"; proposal: Proposal }
export type FramedContentCommitData = { contentType: "commit"; commit: Commit }

export const encodeFramedContentApplicationData: Encoder<FramedContentApplicationData> = contramapEncoders(
  [encodeContentType, encodeVarLenData],
  (f) => [f.contentType, f.applicationData] as const,
)

export const encodeFramedContentProposalData: Encoder<FramedContentProposalData> = contramapEncoders(
  [encodeContentType, encodeProposal],
  (f) => [f.contentType, f.proposal] as const,
)

export const encodeFramedContentCommitData: Encoder<FramedContentCommitData> = contramapEncoders(
  [encodeContentType, encodeCommit],
  (f) => [f.contentType, f.commit] as const,
)

export const encodeFramedContentInfo: Encoder<FramedContentInfo> = (fc) => {
  switch (fc.contentType) {
    case "application":
      return encodeFramedContentApplicationData(fc)
    case "proposal":
      return encodeFramedContentProposalData(fc)
    case "commit":
      return encodeFramedContentCommitData(fc)
  }
}

export const decodeFramedContentApplicationData: Decoder<FramedContentApplicationData> = mapDecoder(
  decodeVarLenData,
  (applicationData) => ({ contentType: "application", applicationData }),
)

export const decodeFramedContentProposalData: Decoder<FramedContentProposalData> = mapDecoder(
  decodeProposal,
  (proposal) => ({ contentType: "proposal", proposal }),
)

export const decodeFramedContentCommitData: Decoder<FramedContentCommitData> = mapDecoder(decodeCommit, (commit) => ({
  contentType: "commit",
  commit,
}))

export const decodeFramedContentInfo: Decoder<FramedContentInfo> = flatMapDecoder(
  decodeContentType,
  (contentType): Decoder<FramedContentInfo> => {
    switch (contentType) {
      case "application":
        return decodeFramedContentApplicationData
      case "proposal":
        return decodeFramedContentProposalData
      case "commit":
        return decodeFramedContentCommitData
    }
  },
)

export function toTbs(content: FramedContent, wireformat: WireformatName, context: GroupContext): FramedContentTBS {
  return { protocolVersion: context.version, wireformat, content, senderType: content.sender.senderType, context }
}

export type FramedContent = FramedContentData & FramedContentInfo
export type FramedContentData = Readonly<{
  groupId: Uint8Array
  epoch: bigint
  sender: Sender
  authenticatedData: Uint8Array
}>

export type FramedContentMember = FramedContent & { sender: SenderMember }
export type FramedContentNewMemberCommit = FramedContent & { sender: SenderNewMemberCommit }

export type FramedContentExternal = FramedContent & { sender: SenderExternal }
export type FramedContentNewMemberProposal = FramedContent & { sender: SenderNewMemberProposal }

export type FramedContentCommit = FramedContentData & FramedContentCommitData
export type FramedContentApplicationOrProposal = FramedContentData &
  (FramedContentApplicationData | FramedContentProposalData)

export const encodeFramedContent: Encoder<FramedContent> = contramapEncoders(
  [encodeVarLenData, encodeUint64, encodeSender, encodeVarLenData, encodeFramedContentInfo],
  (fc) => [fc.groupId, fc.epoch, fc.sender, fc.authenticatedData, fc] as const,
)

export const decodeFramedContent: Decoder<FramedContent> = mapDecoders(
  [decodeVarLenData, decodeUint64, decodeSender, decodeVarLenData, decodeFramedContentInfo],
  (groupId, epoch, sender, authenticatedData, info) => ({
    groupId,
    epoch,
    sender,
    authenticatedData,
    ...info,
  }),
)

type SenderInfo = SenderInfoMember | SenderInfoNewMemberCommit | SenderInfoExternal | SenderInfoNewMemberProposal
type SenderInfoMember = { senderType: "member"; context: GroupContext }
type SenderInfoNewMemberCommit = { senderType: "new_member_commit"; context: GroupContext }
type SenderInfoExternal = { senderType: "external" }
type SenderInfoNewMemberProposal = { senderType: "new_member_proposal" }

export const encodeSenderInfo: Encoder<SenderInfo> = (info) => {
  switch (info.senderType) {
    case "member":
    case "new_member_commit":
      return encodeGroupContext(info.context)
    case "external":
    case "new_member_proposal":
      return new Uint8Array()
  }
}

export const decodeSenderInfo: Decoder<SenderInfo> = flatMapDecoder(
  decodeSenderType,
  (senderType): Decoder<SenderInfo> => {
    switch (senderType) {
      case "member":
        return mapDecoder(decodeGroupContext, (context): SenderInfo => ({ senderType, context }))
      case "new_member_commit":
        return mapDecoder(decodeGroupContext, (context): SenderInfo => ({ senderType, context }))
      case "external":
        return succeedDecoder({ senderType })
      case "new_member_proposal":
        return succeedDecoder({ senderType })
    }
  },
)

export type FramedContentTBS = Readonly<{
  protocolVersion: ProtocolVersionName
  wireformat: WireformatName
  content: FramedContent
}> &
  SenderInfo

export type FramedContentTBSCommit = FramedContentTBS & { content: FramedContentCommit }
export type FramedContentTBSApplicationOrProposal = FramedContentTBS & { content: FramedContentApplicationOrProposal }
export type FramedContentTBSExternal = FramedContentTBS &
  (SenderInfoExternal | SenderInfoNewMemberCommit | SenderInfoNewMemberProposal)

export const encodeFramedContentTBS: Encoder<FramedContentTBS> = contramapEncoders(
  [encodeProtocolVersion, encodeWireformat, encodeFramedContent, encodeSenderInfo],
  (f) => [f.protocolVersion, f.wireformat, f.content, f] as const,
)

export const decodeFramedContentTBS: Decoder<FramedContentTBS> = mapDecoders(
  [decodeProtocolVersion, decodeWireformat, decodeFramedContent, decodeSenderInfo],
  (protocolVersion, wireformat, content, senderContext) => ({ protocolVersion, wireformat, content, ...senderContext }),
)

export type FramedContentAuthData = FramedContentAuthDataCommit | FramedContentAuthDataApplicationOrProposal
export type FramedContentAuthDataCommit = { signature: Uint8Array } & FramedContentAuthDataContentCommit
export type FramedContentAuthDataApplicationOrProposal = {
  signature: Uint8Array
} & FramedContentAuthDataContentApplicationOrProposal
type FramedContentAuthDataContent =
  | FramedContentAuthDataContentCommit
  | FramedContentAuthDataContentApplicationOrProposal
type FramedContentAuthDataContentCommit = { contentType: "commit"; confirmationTag: Uint8Array }
type FramedContentAuthDataContentApplicationOrProposal = { contentType: Exclude<ContentTypeName, "commit"> }

const encodeFramedContentAuthDataContent: Encoder<FramedContentAuthDataContent> = (authData) => {
  switch (authData.contentType) {
    case "commit":
      return encodeFramedContentAuthDataCommit(authData)
    case "application":
    case "proposal":
      return new Uint8Array()
  }
}

const encodeFramedContentAuthDataCommit: Encoder<FramedContentAuthDataContentCommit> = contramapEncoder(
  encodeVarLenData,
  (data) => data.confirmationTag,
)

export const encodeFramedContentAuthData: Encoder<FramedContentAuthData> = contramapEncoders(
  [encodeVarLenData, encodeFramedContentAuthDataContent],
  (d) => [d.signature, d] as const,
)

export const decodeFramedContentAuthDataCommit: Decoder<FramedContentAuthDataContentCommit> = mapDecoder(
  decodeVarLenData,
  (confirmationTag) => ({
    contentType: "commit",
    confirmationTag,
  }),
)

export function decodeFramedContentAuthData(contentType: ContentTypeName): Decoder<FramedContentAuthData> {
  switch (contentType) {
    case "commit":
      return mapDecoders([decodeVarLenData, decodeFramedContentAuthDataCommit], (signature, commitData) => ({
        signature,
        ...commitData,
      }))
    case "application":
    case "proposal":
      return mapDecoder(decodeVarLenData, (signature) => ({
        signature,
        contentType,
      }))
  }
}

export async function signFramedContent(
  signKey: Uint8Array,
  confirmationKey: Uint8Array,
  confirmedTranscriptHash: Uint8Array,
  tbs: FramedContentTBS,
  cs: CiphersuiteImpl,
): Promise<FramedContentAuthData> {
  if (tbs.content.contentType == "commit") {
    return signFramedContentCommit(signKey, confirmationKey, confirmedTranscriptHash, tbs as FramedContentTBSCommit, cs)
  } else {
    return signFramedContentApplicationOrProposal(signKey, tbs as FramedContentTBSApplicationOrProposal, cs)
  }
}

export async function verifyFramedContentSignature(
  signKey: Uint8Array,
  wireformat: WireformatName,
  content: FramedContent,
  auth: FramedContentAuthData,
  context: GroupContext,
  s: Signature,
): Promise<boolean> {
  return verifyWithLabel(
    signKey,
    "FramedContentTBS",
    encodeFramedContentTBS(toTbs(content, wireformat, context)),
    auth.signature,
    s,
  )
}

export async function signFramedContentCommit(
  signKey: Uint8Array,
  confirmationKey: Uint8Array,
  confirmedTranscriptHash: Uint8Array,
  tbs: FramedContentTBSCommit,
  cs: CiphersuiteImpl,
): Promise<FramedContentAuthDataCommit> {
  const signature = await signFramedContentTBS(signKey, tbs, cs.signature)

  return {
    contentType: tbs.content.contentType,
    signature,
    confirmationTag: await createConfirmationTag(confirmationKey, confirmedTranscriptHash, cs.hash),
  }
}

export function signFramedContentTBS(signKey: Uint8Array, tbs: FramedContentTBS, s: Signature): Promise<Uint8Array> {
  return signWithLabel(signKey, "FramedContentTBS", encodeFramedContentTBS(tbs), s)
}

export async function signFramedContentApplicationOrProposal(
  signKey: Uint8Array,
  tbs: FramedContentTBSApplicationOrProposal,
  cs: CiphersuiteImpl,
): Promise<FramedContentAuthDataApplicationOrProposal> {
  const signature = await signFramedContentTBS(signKey, tbs, cs.signature)
  return {
    contentType: tbs.content.contentType,
    signature,
  }
}

export async function verifyFramedContentApplicationOrProposal(
  signKey: Uint8Array,
  tbs: FramedContentTBSApplicationOrProposal,
  auth: FramedContentAuthDataApplicationOrProposal,
  cs: CiphersuiteImpl,
): Promise<boolean> {
  return verifyWithLabel(signKey, "FramedContentTBS", encodeFramedContentTBS(tbs), auth.signature, cs.signature)
}

export function createConfirmationTag(
  confirmationKey: Uint8Array,
  confirmedTranscriptHash: Uint8Array,
  h: Hash,
): Promise<Uint8Array> {
  return h.mac(confirmationKey, confirmedTranscriptHash)
}

export function verifyConfirmationTag(
  confirmationKey: Uint8Array,
  tag: Uint8Array,
  confirmedTranscriptHash: Uint8Array,
  h: Hash,
): Promise<boolean> {
  return h.verifyMac(confirmationKey, tag, confirmedTranscriptHash)
}
export async function createContentCommitSignature(
  groupContext: GroupContext,
  wireformat: WireformatName,
  c: Commit,
  sender: Sender,
  authenticatedData: Uint8Array,
  signKey: Uint8Array,
  s: Signature,
): Promise<{ framedContent: FramedContentCommit; signature: Uint8Array }> {
  const tbs: FramedContentTBSCommit = {
    protocolVersion: groupContext.version,
    wireformat,
    content: {
      contentType: "commit",
      commit: c,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender,
      authenticatedData,
    },
    senderType: "member",
    context: groupContext,
  }

  const signature = await signFramedContentTBS(signKey, tbs, s)
  return { framedContent: tbs.content, signature }
}
