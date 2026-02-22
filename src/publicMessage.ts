import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder, encVoid } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { ExtensionExternalSenders, GroupContextExtension } from "./extension.js"
import { ExternalSender } from "./externalSender.js"
import {
  framedContentDecoder,
  framedContentAuthDataDecoder,
  framedContentEncoder,
  framedContentAuthDataEncoder,
  FramedContent,
  FramedContentAuthData,
} from "./framedContent.js"
import { GroupContext } from "./groupContext.js"
import { ValidationError } from "./mlsError.js"
import { defaultProposalTypes } from "./defaultProposalType.js"
import { defaultExtensionTypes } from "./defaultExtensionType.js"
import { getSignaturePublicKeyFromLeafIndex, RatchetTree } from "./ratchetTree.js"
import { senderTypes, SenderTypeValue } from "./sender.js"
import { toLeafIndex } from "./treemath.js"
import { isDefaultProposal } from "./proposal.js"
import { contentTypes } from "./contentType.js"

/** @public */
export type PublicMessageInfo = PublicMessageInfoMember | PublicMessageInfoMemberOther
/** @public */
export type PublicMessageInfoMember = { senderType: typeof senderTypes.member; membershipTag: Uint8Array }
/** @public */
export type PublicMessageInfoMemberOther = { senderType: Exclude<SenderTypeValue, typeof senderTypes.member> }

const publicMessageInfoEncoder: Encoder<PublicMessageInfo> = (info) => {
  switch (info.senderType) {
    case senderTypes.member:
      return varLenDataEncoder(info.membershipTag)
    case senderTypes.external:
    case senderTypes.new_member_proposal:
    case senderTypes.new_member_commit:
      return encVoid
  }
}

function publicMessageInfoDecoder(senderType: SenderTypeValue): Decoder<PublicMessageInfo> {
  switch (senderType) {
    case senderTypes.member:
      return mapDecoder(varLenDataDecoder, (membershipTag) => ({
        senderType,
        membershipTag,
      }))
    case senderTypes.external:
    case senderTypes.new_member_proposal:
    case senderTypes.new_member_commit:
      return succeedDecoder({ senderType })
  }
}

/** @public */
export type PublicMessage = { content: FramedContent; auth: FramedContentAuthData } & PublicMessageInfo
export type ExternalPublicMessage = PublicMessage & PublicMessageInfoMemberOther

export const publicMessageEncoder: Encoder<PublicMessage> = contramapBufferEncoders(
  [framedContentEncoder, framedContentAuthDataEncoder, publicMessageInfoEncoder],
  (msg) => [msg.content, msg.auth, msg] as const,
)

export const publicMessageDecoder: Decoder<PublicMessage> = flatMapDecoder(framedContentDecoder, (content) =>
  mapDecoders(
    [framedContentAuthDataDecoder(content.contentType), publicMessageInfoDecoder(content.sender.senderType)],
    (auth, info) => ({
      ...info,
      content,
      auth,
    }),
  ),
)

export function findSignaturePublicKey(
  ratchetTree: RatchetTree,
  groupContext: GroupContext,
  framedContent: FramedContent,
): Uint8Array {
  switch (framedContent.sender.senderType) {
    case senderTypes.member:
      return getSignaturePublicKeyFromLeafIndex(ratchetTree, toLeafIndex(framedContent.sender.leafIndex))
    case senderTypes.external: {
      const sender = senderFromExtension(groupContext.extensions, framedContent.sender.senderIndex)
      if (sender === undefined) throw new ValidationError("Received external but no external_sender extension")
      return sender.signaturePublicKey
    }
    case senderTypes.new_member_proposal:
      if (framedContent.contentType !== contentTypes.proposal)
        throw new ValidationError("Received new_member_proposal but contentType is not proposal")
      if (
        !isDefaultProposal(framedContent.proposal) ||
        framedContent.proposal.proposalType !== defaultProposalTypes.add
      )
        throw new ValidationError("Received new_member_proposal but proposalType was not add")

      return framedContent.proposal.add.keyPackage.leafNode.signaturePublicKey
    case senderTypes.new_member_commit: {
      if (framedContent.contentType !== contentTypes.commit)
        throw new ValidationError("Received new_member_commit but contentType is not commit")

      if (framedContent.commit.path === undefined) throw new ValidationError("Commit contains no update path")
      return framedContent.commit.path.leafNode.signaturePublicKey
    }
  }
}

function senderFromExtension(extensions: GroupContextExtension[], senderIndex: number): ExternalSender | undefined {
  const externalSenderExtensions = extensions.filter(
    (ex): ex is ExtensionExternalSenders => ex.extensionType === defaultExtensionTypes.external_senders,
  )

  const externalSenderExtension = externalSenderExtensions[senderIndex]

  if (externalSenderExtension !== undefined) {
    return externalSenderExtension.extensionData
  }
}
