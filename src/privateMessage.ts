import { AuthenticatedContent } from "./authenticatedContent"
import { decodeUint64, encodeUint64 } from "./codec/number"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { decodeCommit, encodeCommit } from "./commit"
import { ContentTypeName, decodeContentType, encodeContentType } from "./contentType"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import {
  decodeFramedContentAuthDataCommit,
  encodeFramedContentAuthData,
  FramedContentApplicationData,
  FramedContentAuthDataApplicationOrProposal,
  FramedContentAuthDataCommit,
  FramedContentCommitData,
  FramedContentProposalData,
} from "./framedContent"
import { byteLengthToPad, PaddingConfig } from "./paddingConfig"
import { decodeProposal, encodeProposal } from "./proposal"
import {
  decodeSenderData,
  encodeSenderData,
  encodeSenderDataAAD,
  expandSenderDataKey,
  expandSenderDataNonce,
  SenderData,
  SenderDataAAD,
} from "./sender"

export interface PrivateMessage {
  groupId: Uint8Array
  epoch: bigint
  contentType: ContentTypeName
  authenticatedData: Uint8Array
  encryptedSenderData: Uint8Array
  ciphertext: Uint8Array
}

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

export interface PrivateContentAAD {
  groupId: Uint8Array
  epoch: bigint
  contentType: ContentTypeName
  authenticatedData: Uint8Array
}

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

export function decodePrivateMessageContent(contentType: ContentTypeName): Decoder<PrivateMessageContent> {
  switch (contentType) {
    case "application":
      return decoderWithPadding(
        mapDecoders([decodeVarLenData, decodeVarLenData], (applicationData, signature) => ({
          contentType,
          applicationData,
          auth: { contentType, signature },
        })),
      )
    case "proposal":
      return decoderWithPadding(
        mapDecoders([decodeProposal, decodeVarLenData], (proposal, signature) => ({
          contentType,
          proposal,
          auth: { contentType, signature },
        })),
      )
    case "commit":
      return decoderWithPadding(
        mapDecoders([decodeCommit, decodeVarLenData, decodeFramedContentAuthDataCommit], (commit, signature, auth) => ({
          contentType,
          commit,
          auth: { ...auth, signature, contentType },
        })),
      )
  }
}

export function encodePrivateMessageContent(config: PaddingConfig): Encoder<PrivateMessageContent> {
  return (msg) => {
    switch (msg.contentType) {
      case "application":
        return encoderWithPadding(
          contramapEncoders(
            [encodeVarLenData, encodeFramedContentAuthData],
            (m: PrivateMessageContentApplication) => [m.applicationData, m.auth] as const,
          ),
          config,
        )(msg)

      case "proposal":
        return encoderWithPadding(
          contramapEncoders(
            [encodeProposal, encodeFramedContentAuthData],
            (m: PrivateMessageContentProposal) => [m.proposal, m.auth] as const,
          ),
          config,
        )(msg)

      case "commit":
        return encoderWithPadding(
          contramapEncoders(
            [encodeCommit, encodeFramedContentAuthData],
            (m: PrivateMessageContentCommit) => [m.commit, m.auth] as const,
          ),
          config,
        )(msg)
    }
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

function encoderWithPadding<T>(encoder: Encoder<T>, config: PaddingConfig): Encoder<T> {
  return (t) => {
    const encoded = encoder(t)
    const result = new Uint8Array(encoded.length + byteLengthToPad(encoded.length, config))
    result.set(encoded, 0)

    return result
  }
}

function decoderWithPadding<T>(decoder: Decoder<T>): Decoder<T> {
  return (bytes, offset) => {
    const result = decoder(bytes, offset)
    if (result === undefined) return undefined
    const [decoded, innerOffset] = result

    const paddingBytes = bytes.subarray(offset + innerOffset, bytes.length)

    const allZeroes = paddingBytes.every((byte) => byte === 0)

    if (!allZeroes) return undefined

    return [decoded, bytes.length]
  }
}
