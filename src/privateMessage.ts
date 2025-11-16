import { AuthenticatedContent } from "./authenticatedContent.js"
import { decodeUint64, encUint64 } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapEncs, Enc, encode } from "./codec/tlsEncoder.js"
import { decodeVarLenData, encVarLenData } from "./codec/variableLength.js"
import { decodeCommit, encodeCommit } from "./commit.js"
import { ContentTypeName, decodeContentType, encodeContentType } from "./contentType.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import {
  decodeFramedContentAuthDataCommit,
  encodeFramedContentAuthData,
  FramedContentApplicationData,
  FramedContentAuthDataApplicationOrProposal,
  FramedContentAuthDataCommit,
  FramedContentCommitData,
  FramedContentProposalData,
} from "./framedContent.js"
import { byteLengthToPad, PaddingConfig } from "./paddingConfig.js"
import { decodeProposal, encodeProposal } from "./proposal.js"
import {
  decodeSenderData,
  encodeSenderData,
  encodeSenderDataAAD,
  expandSenderDataKey,
  expandSenderDataNonce,
  SenderData,
  SenderDataAAD,
} from "./sender.js"

export interface PrivateMessage {
  groupId: Uint8Array
  epoch: bigint
  contentType: ContentTypeName
  authenticatedData: Uint8Array
  encryptedSenderData: Uint8Array
  ciphertext: Uint8Array
}

export const encodePrivateMessage: Enc<PrivateMessage> = contramapEncs(
  [encVarLenData, encUint64, encodeContentType, encVarLenData, encVarLenData, encVarLenData],
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

export const encodePrivateContentAAD: Enc<PrivateContentAAD> = contramapEncs(
  [encVarLenData, encUint64, encodeContentType, encVarLenData],
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

export function encodePrivateMessageContent(config: PaddingConfig): Enc<PrivateMessageContent> {
  return (msg) => {
    switch (msg.contentType) {
      case "application":
        return encoderWithPadding(
          contramapEncs(
            [encVarLenData, encodeFramedContentAuthData],
            (m: PrivateMessageContentApplication) => [m.applicationData, m.auth] as const,
          ),
          config,
        )(msg)

      case "proposal":
        return encoderWithPadding(
          contramapEncs(
            [encodeProposal, encodeFramedContentAuthData],
            (m: PrivateMessageContentProposal) => [m.proposal, m.auth] as const,
          ),
          config,
        )(msg)

      case "commit":
        return encoderWithPadding(
          contramapEncs(
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

  const decrypted = await cs.hpke.decryptAead(key, nonce, encode(encodeSenderDataAAD)(aad), msg.encryptedSenderData)
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

  return await cs.hpke.encryptAead(key, nonce, encode(encodeSenderDataAAD)(aad), encode(encodeSenderData)(senderData))
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

function encoderWithPadding<T>(encoder: Enc<T>, config: PaddingConfig): Enc<T> {
  return (t) => {
    const [len, write] = encoder(t)
    const totalLength = len + byteLengthToPad(len, config)
    return [totalLength, (offset, buffer) => {
      write(offset, buffer)
    }]
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
