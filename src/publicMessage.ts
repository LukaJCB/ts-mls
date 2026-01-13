import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder, encVoid } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { Extension } from "./extension.js"
import { decodeExternalSender, ExternalSender } from "./externalSender.js"
import {
  decodeFramedContent,
  decodeFramedContentAuthData,
  framedContentEncoder,
  framedContentAuthDataEncoder,
  FramedContent,
  FramedContentAuthData,
} from "./framedContent.js"
import { GroupContext } from "./groupContext.js"
import { CodecError, ValidationError } from "./mlsError.js"
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

export const publicMessageInfoEncoder: BufferEncoder<PublicMessageInfo> = (info) => {
  switch (info.senderType) {
    case senderTypes.member:
      return varLenDataEncoder(info.membershipTag)
    case senderTypes.external:
    case senderTypes.new_member_proposal:
    case senderTypes.new_member_commit:
      return encVoid
  }
}

export const encodePublicMessageInfo: Encoder<PublicMessageInfo> = encode(publicMessageInfoEncoder)

export function decodePublicMessageInfo(senderType: SenderTypeValue): Decoder<PublicMessageInfo> {
  switch (senderType) {
    case senderTypes.member:
      return mapDecoder(decodeVarLenData, (membershipTag) => ({
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
export type MemberPublicMessage = PublicMessage & PublicMessageInfoMember
export type ExternalPublicMessage = PublicMessage & PublicMessageInfoMemberOther

export const publicMessageEncoder: BufferEncoder<PublicMessage> = contramapBufferEncoders(
  [framedContentEncoder, framedContentAuthDataEncoder, publicMessageInfoEncoder],
  (msg) => [msg.content, msg.auth, msg] as const,
)

export const encodePublicMessage: Encoder<PublicMessage> = encode(publicMessageEncoder)

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

export function senderFromExtension(extensions: Extension[], senderIndex: number): ExternalSender | undefined {
  const externalSenderExtensions = extensions.filter(
    (ex) => ex.extensionType === defaultExtensionTypes.external_senders,
  )

  const externalSenderExtension = externalSenderExtensions[senderIndex]

  if (externalSenderExtension !== undefined) {
    const externalSender = decodeExternalSender(externalSenderExtension.extensionData, 0)
    if (externalSender === undefined) throw new CodecError("Could not decode ExternalSender")

    return externalSender[0]
  }
}
