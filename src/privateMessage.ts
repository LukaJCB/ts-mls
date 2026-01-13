import { AuthenticatedContent } from "./authenticatedContent.js"
import { uint64Decoder, uint64Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { commitDecoder, commitEncoder } from "./commit.js"
import { ContentTypeValue, contentTypes, contentTypeEncoder, contentTypeDecoder } from "./contentType.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import {
  framedContentAuthDataCommitDecoder,
  framedContentAuthDataEncoder,
  FramedContentApplicationData,
  FramedContentAuthDataApplicationOrProposal,
  FramedContentAuthDataCommit,
  FramedContentCommitData,
  FramedContentProposalData,
} from "./framedContent.js"
import { byteLengthToPad, PaddingConfig } from "./paddingConfig.js"
import { proposalDecoder, proposalEncoder } from "./proposal.js"
import {
  senderDataDecoder,
  senderDataEncoder,
  senderDataAADEncoder,
  expandSenderDataKey,
  expandSenderDataNonce,
  senderTypes,
  SenderData,
  SenderDataAAD,
} from "./sender.js"
import { wireformats } from "./wireformat.js"

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

export const privateMessageDecoder: Decoder<PrivateMessage> = mapDecoders(
  [varLenDataDecoder, uint64Decoder, contentTypeDecoder, varLenDataDecoder, varLenDataDecoder, varLenDataDecoder],
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

export const privateContentAADDecoder: Decoder<PrivateContentAAD> = mapDecoders(
  [varLenDataDecoder, uint64Decoder, contentTypeDecoder, varLenDataDecoder],
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

export function privateMessageContentDecoder(contentType: ContentTypeValue): Decoder<PrivateMessageContent> {
  switch (contentType) {
    case contentTypes.application:
      return decoderWithPadding(
        mapDecoders([varLenDataDecoder, varLenDataDecoder], (applicationData, signature) => ({
          contentType,
          applicationData,
          auth: { contentType, signature },
        })),
      )
    case contentTypes.proposal:
      return decoderWithPadding(
        mapDecoders([proposalDecoder, varLenDataDecoder], (proposal, signature) => ({
          contentType,
          proposal,
          auth: { contentType, signature },
        })),
      )
    case contentTypes.commit:
      return decoderWithPadding(
        mapDecoders(
          [commitDecoder, varLenDataDecoder, framedContentAuthDataCommitDecoder],
          (commit, signature, auth) => ({
            contentType,
            commit,
            auth: { ...auth, signature, contentType },
          }),
        ),
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

  const decrypted = await cs.hpke.decryptAead(key, nonce, encode(senderDataAADEncoder, aad), msg.encryptedSenderData)
  return senderDataDecoder(decrypted, 0)?.[0]
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

  return await cs.hpke.encryptAead(key, nonce, encode(senderDataAADEncoder, aad), encode(senderDataEncoder, senderData))
}

export function toAuthenticatedContent(
  content: PrivateMessageContent,
  msg: PrivateMessage,
  senderLeafIndex: number,
): AuthenticatedContent {
  return {
    wireformat: wireformats.mls_private_message,
    content: {
      groupId: msg.groupId,
      epoch: msg.epoch,
      sender: {
        senderType: senderTypes.member,
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
