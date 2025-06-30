import { AuthenticatedContent } from "./authenticatedContent"
import { decodeUint64, encodeUint64 } from "./codec/number"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { decodeCommit, encodeCommit } from "./commit"
import { ContentTypeName, decodeContentType, encodeContentType } from "./contentType"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import {
  decodeFramedContent,
  decodeFramedContentAuthDataCommit,
  encodeFramedContentAuthData,
  FramedContent,
  FramedContentApplicationData,
  FramedContentAuthDataApplicationOrProposal,
  FramedContentAuthDataCommit,
  FramedContentCommitData,
  FramedContentProposalData,
} from "./framedContent"
import { GroupContext } from "./groupContext"
import { CryptoError } from "./mlsError"
import { decodeProposal, encodeProposal } from "./proposal"
import { deriveKey, deriveNonce, GenerationSecret } from "./secretTree"
import {
  decodeSenderData,
  encodeSenderData,
  encodeSenderDataAAD,
  expandSenderDataKey,
  expandSenderDataNonce,
  SenderData,
  SenderDataAAD,
} from "./sender"

export type PrivateMessage = Readonly<{
  groupId: Uint8Array
  epoch: bigint
  contentType: ContentTypeName
  authenticatedData: Uint8Array
  encryptedSenderData: Uint8Array
  ciphertext: Uint8Array
}>

export const encodePrivateMessage: Encoder<PrivateMessage> = contramapEncoders(
  [encodeVarLenData, encodeUint64, encodeContentType, encodeVarLenData, encodeVarLenData, encodeVarLenData],
  (msg) =>
    [msg.groupId, msg.epoch, msg.contentType, msg.authenticatedData, msg.encryptedSenderData, msg.ciphertext] as const,
)

export const decodePrivateMessage: Decoder<PrivateMessage> = mapDecoders(
  [decodeVarLenData, decodeUint64, decodeContentType, decodeVarLenData, decodeVarLenData, decodeVarLenData],
  (groupId, epoch, contentType, authenticatedData, encryptedSenderData, ciphertext) => ({
    groupId,
    epoch,
    contentType,
    authenticatedData,
    encryptedSenderData,
    ciphertext,
  }),
)

export type PrivateContentAAD = Readonly<{
  groupId: Uint8Array
  epoch: bigint
  contentType: ContentTypeName
  authenticatedData: Uint8Array
}>

export const encodePrivateContentAAD: Encoder<PrivateContentAAD> = contramapEncoders(
  [encodeVarLenData, encodeUint64, encodeContentType, encodeVarLenData],
  (aad) => [aad.groupId, aad.epoch, aad.contentType, aad.authenticatedData] as const,
)

export const decodePrivateContentAAD: Decoder<PrivateContentAAD> = mapDecoders(
  [decodeVarLenData, decodeUint64, decodeContentType, decodeVarLenData],
  (groupId, epoch, contentType, authenticatedData) => ({
    groupId,
    epoch,
    contentType,
    authenticatedData,
  }),
)

export type PrivateMessageContent =
  | PrivateMessageContentApplication
  | PrivateMessageContentProposal
  | PrivateMessageContentCommit
export type PrivateMessageContentApplication = FramedContentApplicationData & {
  auth: FramedContentAuthDataApplicationOrProposal
}
export type PrivateMessageContentProposal = FramedContentProposalData & {
  auth: FramedContentAuthDataApplicationOrProposal
}
export type PrivateMessageContentCommit = FramedContentCommitData & { auth: FramedContentAuthDataCommit }

//todo padding?
export function decodePrivateMessageContent(contentType: ContentTypeName): Decoder<PrivateMessageContent> {
  switch (contentType) {
    case "application":
      return mapDecoders([decodeVarLenData, decodeVarLenData], (applicationData, signature) => ({
        contentType,
        applicationData,
        auth: { contentType, signature },
      }))
    case "proposal":
      return mapDecoders([decodeProposal, decodeVarLenData], (proposal, signature) => ({
        contentType,
        proposal,
        auth: { contentType, signature },
      }))
    case "commit":
      return mapDecoders(
        [decodeCommit, decodeVarLenData, decodeFramedContentAuthDataCommit],
        (commit, signature, auth) => ({
          contentType,
          commit,
          auth: { ...auth, signature, contentType },
        }),
      )
  }
}

export const encodePrivateMessageContent: Encoder<PrivateMessageContent> = (msg) => {
  switch (msg.contentType) {
    case "application":
      return contramapEncoders(
        [encodeVarLenData, encodeFramedContentAuthData],
        (m: PrivateMessageContentApplication) => [m.applicationData, m.auth] as const,
      )(msg)

    case "proposal":
      return contramapEncoders(
        [encodeProposal, encodeFramedContentAuthData],
        (m: PrivateMessageContentProposal) => [m.proposal, m.auth] as const,
      )(msg)

    case "commit":
      return contramapEncoders(
        [encodeCommit, encodeFramedContentAuthData],
        (m: PrivateMessageContentCommit) => [m.commit, m.auth] as const,
      )(msg)
  }
}

export async function decryptSenderData(
  msg: PrivateMessage,
  senderDataSecret: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<SenderData | undefined> {
  const key = await expandSenderDataKey(cs, senderDataSecret, msg.ciphertext)
  const nonce = await expandSenderDataNonce(cs, senderDataSecret, msg.ciphertext)

  const aad: SenderDataAAD = {
    groupId: msg.groupId,
    epoch: msg.epoch,
    contentType: msg.contentType,
  }

  const decrypted = await cs.hpke.decryptAead(key, nonce, encodeSenderDataAAD(aad), msg.encryptedSenderData)
  return decodeSenderData(decrypted, 0)?.[0]
}

export async function encryptSenderData(
  senderDataSecret: Uint8Array,
  senderData: SenderData,
  aad: SenderDataAAD,
  ciphertext: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<Uint8Array> {
  const key = await expandSenderDataKey(cs, senderDataSecret, ciphertext)
  const nonce = await expandSenderDataNonce(cs, senderDataSecret, ciphertext)

  return await cs.hpke.encryptAead(key, nonce, encodeSenderDataAAD(aad), encodeSenderData(senderData))
}

export async function decryptContent(
  msg: PrivateMessage,
  secret: GenerationSecret,
  reuseGuard: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<FramedContent | undefined> {
  const key = await deriveKey(secret.secret, secret.generation, cs)
  const nonce = await derivePrivateMessageNonce(secret, reuseGuard, cs)

  const aad: PrivateContentAAD = {
    groupId: msg.groupId,
    epoch: msg.epoch,
    contentType: msg.contentType,
    authenticatedData: msg.authenticatedData,
  }

  const decrypted = await cs.hpke.decryptAead(key, nonce, encodePrivateContentAAD(aad), msg.ciphertext)

  return decodeFramedContent(decrypted, 0)?.[0]
}

export async function derivePrivateMessageNonce(
  secret: GenerationSecret,
  reuseGuard: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<Uint8Array> {
  const nonce = await deriveNonce(secret.secret, secret.generation, cs)

  if (nonce.length >= 4 && reuseGuard.length >= 4) {
    for (let i = 0; i < 4; i++) {
      nonce[i]! ^= reuseGuard[i]!
    }
  } else throw new CryptoError("Reuse guard or nonce incorrect length")

  return nonce
}

export function toAuthenticatedContent(
  content: PrivateMessageContent,
  msg: PrivateMessage,
  senderLeafIndex: number,
): AuthenticatedContent {
  return {
    wireformat: "mls_private_message",
    content: {
      groupId: msg.groupId,
      epoch: msg.epoch,
      sender: {
        senderType: "member",
        leafIndex: senderLeafIndex,
      },
      authenticatedData: msg.authenticatedData,
      ...content,
    },
    auth: content.auth,
  }
}

export function privateMessageContentToAuthenticatedContent(
  c: PrivateMessageContent,
  groupContext: GroupContext,
  leafIndex: number,
  authenticatedData: Uint8Array,
): AuthenticatedContent {
  return {
    wireformat: "mls_private_message",
    content: {
      ...c,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender: { senderType: "member", leafIndex },
      authenticatedData,
    },
    auth: c.auth,
  }
}
