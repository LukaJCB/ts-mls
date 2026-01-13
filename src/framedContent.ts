import { uint64Decoder, uint64Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, contramapBufferEncoders, BufferEncoder, encode, encVoid } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { Commit, commitDecoder, commitEncoder } from "./commit.js"
import { ContentTypeValue, contentTypes, contentTypeEncoder, contentTypeDecoder } from "./contentType.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Hash } from "./crypto/hash.js"
import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature.js"
import { groupContextEncoder, GroupContext } from "./groupContext.js"
import { wireformatEncoder, WireformatName, wireformats, WireformatValue } from "./wireformat.js"
import { proposalDecoder, proposalEncoder, Proposal } from "./proposal.js"
import { protocolVersionEncoder, ProtocolVersionValue } from "./protocolVersion.js"
import { senderDecoder, senderEncoder, Sender } from "./sender.js"
import { senderTypes } from "./sender.js"

/** @public */
export type FramedContentInfo = FramedContentApplicationData | FramedContentProposalData | FramedContentCommitData

/** @public */
export interface FramedContentApplicationData {
  contentType: typeof contentTypes.application
  applicationData: Uint8Array
}
/** @public */
export interface FramedContentProposalData {
  contentType: typeof contentTypes.proposal
  proposal: Proposal
}
/** @public */
export interface FramedContentCommitData {
  contentType: typeof contentTypes.commit
  commit: Commit
}

export const framedContentApplicationDataEncoder: BufferEncoder<FramedContentApplicationData> = contramapBufferEncoders(
  [contentTypeEncoder, varLenDataEncoder],
  (f) => [f.contentType, f.applicationData] as const,
)

export const framedContentProposalDataEncoder: BufferEncoder<FramedContentProposalData> = contramapBufferEncoders(
  [contentTypeEncoder, proposalEncoder],
  (f) => [f.contentType, f.proposal] as const,
)

export const framedContentCommitDataEncoder: BufferEncoder<FramedContentCommitData> = contramapBufferEncoders(
  [contentTypeEncoder, commitEncoder],
  (f) => [f.contentType, f.commit] as const,
)

export const framedContentInfoEncoder: BufferEncoder<FramedContentInfo> = (fc) => {
  switch (fc.contentType) {
    case contentTypes.application:
      return framedContentApplicationDataEncoder(fc)
    case contentTypes.proposal:
      return framedContentProposalDataEncoder(fc)
    case contentTypes.commit:
      return framedContentCommitDataEncoder(fc)
  }
}

export const framedContentApplicationDataDecoder: Decoder<FramedContentApplicationData> = mapDecoder(
  varLenDataDecoder,
  (applicationData) => ({ contentType: contentTypes.application, applicationData }),
)

export const framedContentProposalDataDecoder: Decoder<FramedContentProposalData> = mapDecoder(
  proposalDecoder,
  (proposal) => ({ contentType: contentTypes.proposal, proposal }),
)

export const framedContentCommitDataDecoder: Decoder<FramedContentCommitData> = mapDecoder(commitDecoder, (commit) => ({
  contentType: contentTypes.commit,
  commit,
}))

export const framedContentInfoDecoder: Decoder<FramedContentInfo> = flatMapDecoder(
  contentTypeDecoder,
  (contentType): Decoder<FramedContentInfo> => {
    switch (contentType) {
      case contentTypes.application:
        return framedContentApplicationDataDecoder
      case contentTypes.proposal:
        return framedContentProposalDataDecoder
      case contentTypes.commit:
        return framedContentCommitDataDecoder
    }
  },
)

export function toTbs(content: FramedContent, wireformat: WireformatValue, context: GroupContext): FramedContentTBS {
  return { protocolVersion: context.version, wireformat, content, senderType: content.sender.senderType, context }
}

/** @public */
export type FramedContent = FramedContentData & FramedContentInfo
/** @public */
export interface FramedContentData {
  groupId: Uint8Array
  epoch: bigint
  sender: Sender
  authenticatedData: Uint8Array
}

export type FramedContentCommit = FramedContentData & FramedContentCommitData
export type FramedContentApplicationOrProposal = FramedContentData &
  (FramedContentApplicationData | FramedContentProposalData)

export const framedContentEncoder: BufferEncoder<FramedContent> = contramapBufferEncoders(
  [varLenDataEncoder, uint64Encoder, senderEncoder, varLenDataEncoder, framedContentInfoEncoder],
  (fc) => [fc.groupId, fc.epoch, fc.sender, fc.authenticatedData, fc] as const,
)

export const framedContentDecoder: Decoder<FramedContent> = mapDecoders(
  [varLenDataDecoder, uint64Decoder, senderDecoder, varLenDataDecoder, framedContentInfoDecoder],
  (groupId, epoch, sender, authenticatedData, info) => ({
    groupId,
    epoch,
    sender,
    authenticatedData,
    ...info,
  }),
)

type SenderInfo = SenderInfoMember | SenderInfoNewMemberCommit | SenderInfoExternal | SenderInfoNewMemberProposal
type SenderInfoMember = { senderType: typeof senderTypes.member; context: GroupContext }
type SenderInfoNewMemberCommit = { senderType: typeof senderTypes.new_member_commit; context: GroupContext }
type SenderInfoExternal = { senderType: typeof senderTypes.external }
type SenderInfoNewMemberProposal = { senderType: typeof senderTypes.new_member_proposal }

export const senderInfoEncoder: BufferEncoder<SenderInfo> = (info) => {
  switch (info.senderType) {
    case senderTypes.member:
    case senderTypes.new_member_commit:
      return groupContextEncoder(info.context)
    case senderTypes.external:
    case senderTypes.new_member_proposal:
      return encVoid
  }
}

export type FramedContentTBS = {
  protocolVersion: ProtocolVersionValue
  wireformat: WireformatValue
  content: FramedContent
} & SenderInfo

export type FramedContentTBSCommit = FramedContentTBS & { content: FramedContentCommit }
export type FramedContentTBSApplicationOrProposal = FramedContentTBS & { content: FramedContentApplicationOrProposal }

export const framedContentTBSEncoder: BufferEncoder<FramedContentTBS> = contramapBufferEncoders(
  [protocolVersionEncoder, wireformatEncoder, framedContentEncoder, senderInfoEncoder],
  (f) => [f.protocolVersion, f.wireformat, f.content, f] as const,
)

/** @public */
export type FramedContentAuthData = FramedContentAuthDataCommit | FramedContentAuthDataApplicationOrProposal
/** @public */
export type FramedContentAuthDataCommit = { signature: Uint8Array } & FramedContentAuthDataContentCommit
/** @public */
export type FramedContentAuthDataApplicationOrProposal = {
  signature: Uint8Array
} & FramedContentAuthDataContentApplicationOrProposal
type FramedContentAuthDataContent =
  | FramedContentAuthDataContentCommit
  | FramedContentAuthDataContentApplicationOrProposal
/** @public */
export type FramedContentAuthDataContentCommit = {
  contentType: typeof contentTypes.commit
  confirmationTag: Uint8Array
}
/** @public */
export type FramedContentAuthDataContentApplicationOrProposal = {
  contentType: typeof contentTypes.application | typeof contentTypes.proposal
}

const encodeFramedContentAuthDataContent: BufferEncoder<FramedContentAuthDataContent> = (authData) => {
  switch (authData.contentType) {
    case contentTypes.commit:
      return encodeFramedContentAuthDataCommit(authData)
    case contentTypes.application:
    case contentTypes.proposal:
      return encVoid
  }
}

const encodeFramedContentAuthDataCommit: BufferEncoder<FramedContentAuthDataContentCommit> = contramapBufferEncoder(
  varLenDataEncoder,
  (data) => data.confirmationTag,
)

export const framedContentAuthDataEncoder: BufferEncoder<FramedContentAuthData> = contramapBufferEncoders(
  [varLenDataEncoder, encodeFramedContentAuthDataContent],
  (d) => [d.signature, d] as const,
)

export const framedContentAuthDataCommitDecoder: Decoder<FramedContentAuthDataContentCommit> = mapDecoder(
  varLenDataDecoder,
  (confirmationTag) => ({
    contentType: contentTypes.commit,
    confirmationTag,
  }),
)

export function framedContentAuthDataDecoder(contentType: ContentTypeValue): Decoder<FramedContentAuthData> {
  switch (contentType) {
    case contentTypes.commit:
      return mapDecoders([varLenDataDecoder, framedContentAuthDataCommitDecoder], (signature, commitData) => ({
        signature,
        ...commitData,
      }))
    case contentTypes.application:
    case contentTypes.proposal:
      return mapDecoder(varLenDataDecoder, (signature) => ({
        signature,
        contentType,
      }))
  }
}

export async function verifyFramedContentSignature(
  signKey: Uint8Array,
  wireformat: WireformatValue,
  content: FramedContent,
  auth: FramedContentAuthData,
  context: GroupContext,
  s: Signature,
): Promise<boolean> {
  return verifyWithLabel(
    signKey,
    "FramedContentTBS",
    encode(framedContentTBSEncoder, toTbs(content, wireformat, context)),
    auth.signature,
    s,
  )
}

export function signFramedContentTBS(signKey: Uint8Array, tbs: FramedContentTBS, s: Signature): Promise<Uint8Array> {
  return signWithLabel(signKey, "FramedContentTBS", encode(framedContentTBSEncoder, tbs), s)
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
    wireformat: wireformats[wireformat],
    content: {
      contentType: contentTypes.commit,
      commit: c,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender,
      authenticatedData,
    },
    senderType: sender.senderType,
    context: groupContext,
  }

  const signature = await signFramedContentTBS(signKey, tbs, s)
  return { framedContent: tbs.content, signature }
}
