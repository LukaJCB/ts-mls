import { AuthenticatedContent } from "./authenticatedContent.js"
import { decodeUint64, uint64Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { decodeCommit, commitEncoder } from "./commit.js"
import { ContentTypeValue, contentTypes, contentTypeEncoder, decodeContentType } from "./contentType.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import {
  decodeFramedContentAuthDataCommit,
  framedContentAuthDataEncoder,
  FramedContentApplicationData,
  FramedContentAuthDataApplicationOrProposal,
  FramedContentAuthDataCommit,
  FramedContentCommitData,
  FramedContentProposalData,
} from "./framedContent.js"
import { byteLengthToPad, PaddingConfig } from "./paddingConfig.js"
import { decodeProposal, proposalEncoder } from "./proposal.js"
import {
  decodeSenderData,
  senderDataEncoder,
  senderDataAADEncoder,
  expandSenderDataKey,
  expandSenderDataNonce,
  SenderData,
  SenderDataAAD,
} from "./sender.js"

/** @public */
export interface PrivateMessage {
  groupId: Uint8Array
  epoch: bigint
  contentType: ContentTypeValue
  authenticatedData: Uint8Array
  encryptedSenderData: Uint8Array
  ciphertext: Uint8Array
}

export const privateMessageEncoder: BufferEncoder<PrivateMessage> = contramapBufferEncoders(
  [varLenDataEncoder, uint64Encoder, contentTypeEncoder, varLenDataEncoder, varLenDataEncoder, varLenDataEncoder],
  (msg) =>
    [msg.groupId, msg.epoch, msg.contentType, msg.authenticatedData, msg.encryptedSenderData, msg.ciphertext] as const,
)

export const encodePrivateMessage: Encoder<PrivateMessage> = encode(privateMessageEncoder)

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
  contentType: ContentTypeValue
  authenticatedData: Uint8Array
}

export const privateContentAADEncoder: BufferEncoder<PrivateContentAAD> = contramapBufferEncoders(
  [varLenDataEncoder, uint64Encoder, contentTypeEncoder, varLenDataEncoder],
  (aad) => [aad.groupId, aad.epoch, aad.contentType, aad.authenticatedData] as const,
)

export const encodePrivateContentAAD: Encoder<PrivateContentAAD> = encode(privateContentAADEncoder)

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

export function decodePrivateMessageContent(contentType: ContentTypeValue): Decoder<PrivateMessageContent> {
  switch (contentType) {
    case contentTypes.application:
      return decoderWithPadding(
        mapDecoders([decodeVarLenData, decodeVarLenData], (applicationData, signature) => ({
          contentType,
          applicationData,
          auth: { contentType, signature },
        })),
      )
    case contentTypes.proposal:
      return decoderWithPadding(
        mapDecoders([decodeProposal, decodeVarLenData], (proposal, signature) => ({
          contentType,
          proposal,
          auth: { contentType, signature },
        })),
      )
    case contentTypes.commit:
      return decoderWithPadding(
        mapDecoders([decodeCommit, decodeVarLenData, decodeFramedContentAuthDataCommit], (commit, signature, auth) => ({
          contentType,
          commit,
          auth: { ...auth, signature, contentType },
        })),
      )
  }
}

export function privateMessageContentEncoder(config: PaddingConfig): BufferEncoder<PrivateMessageContent> {
  return (msg) => {
    switch (msg.contentType) {
      case contentTypes.application:
        return encoderWithPadding(
          contramapBufferEncoders(
            [varLenDataEncoder, framedContentAuthDataEncoder],
            (m: PrivateMessageContentApplication) => [m.applicationData, m.auth] as const,
          ),
          config,
        )(msg)

      case contentTypes.proposal:
        return encoderWithPadding(
          contramapBufferEncoders(
            [proposalEncoder, framedContentAuthDataEncoder],
            (m: PrivateMessageContentProposal) => [m.proposal, m.auth] as const,
          ),
          config,
        )(msg)

      case contentTypes.commit:
        return encoderWithPadding(
          contramapBufferEncoders(
            [commitEncoder, framedContentAuthDataEncoder],
            (m: PrivateMessageContentCommit) => [m.commit, m.auth] as const,
          ),
          config,
        )(msg)
    }
  }
}

export function encodePrivateMessageContent(config: PaddingConfig): Encoder<PrivateMessageContent> {
  return encode(privateMessageContentEncoder(config))
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

  const decrypted = await cs.hpke.decryptAead(key, nonce, encode(senderDataAADEncoder)(aad), msg.encryptedSenderData)
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

  return await cs.hpke.encryptAead(key, nonce, encode(senderDataAADEncoder)(aad), encode(senderDataEncoder)(senderData))
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

function encoderWithPadding<T>(encoder: BufferEncoder<T>, config: PaddingConfig): BufferEncoder<T> {
  return (t) => {
    const [len, write] = encoder(t)
    const totalLength = len + byteLengthToPad(len, config)
    return [
      totalLength,
      (offset, buffer) => {
        write(offset, buffer)
      },
    ]
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
