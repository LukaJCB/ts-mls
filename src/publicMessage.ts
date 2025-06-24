import { AuthenticatedContentTBM, createMembershipTag } from "./authenticatedContent"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
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

export function findSignaturePublicKey(
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
