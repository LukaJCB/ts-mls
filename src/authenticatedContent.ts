import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { Hash, refhash } from "./crypto/hash.js"
import {
  decodeFramedContent,
  decodeFramedContentAuthData,
  framedContentEncoder,
  framedContentAuthDataEncoder,
  framedContentTBSEncoder,
  FramedContent,
  FramedContentApplicationData,
  FramedContentAuthData,
  FramedContentCommitData,
  FramedContentData,
  FramedContentProposalData,
  FramedContentTBS,
} from "./framedContent.js"
import { decodeWireformat, wireformatEncoder, WireformatValue } from "./wireformat.js"

export interface AuthenticatedContent {
  wireformat: WireformatValue
  content: FramedContent
  auth: FramedContentAuthData
}

export type AuthenticatedContentApplication = AuthenticatedContent & {
  content: FramedContentApplicationData & FramedContentData
}

export type AuthenticatedContentCommit = AuthenticatedContent & {
  content: FramedContentCommitData & FramedContentData
}

export type AuthenticatedContentProposal = AuthenticatedContent & {
  content: FramedContentProposalData & FramedContentData
}

export type AuthenticatedContentProposalOrCommit = AuthenticatedContent & {
  content: (FramedContentProposalData | FramedContentCommitData) & FramedContentData
}
export const authenticatedContentEncoder: BufferEncoder<AuthenticatedContent> = contramapBufferEncoders(
  [wireformatEncoder, framedContentEncoder, framedContentAuthDataEncoder],
  (a) => [a.wireformat, a.content, a.auth] as const,
)

export const encodeAuthenticatedContent: Encoder<AuthenticatedContent> = encode(authenticatedContentEncoder)

export const decodeAuthenticatedContent: Decoder<AuthenticatedContent> = mapDecoders(
  [
    decodeWireformat,
    flatMapDecoder(decodeFramedContent, (content) => {
      return mapDecoder(decodeFramedContentAuthData(content.contentType), (auth) => ({ content, auth }))
    }),
  ],
  (wireformat, contentAuth) => ({
    wireformat,
    ...contentAuth,
  }),
)

export interface AuthenticatedContentTBM {
  contentTbs: FramedContentTBS
  auth: FramedContentAuthData
}

export const authenticatedContentTBMEncoder: BufferEncoder<AuthenticatedContentTBM> = contramapBufferEncoders(
  [framedContentTBSEncoder, framedContentAuthDataEncoder],
  (t) => [t.contentTbs, t.auth] as const,
)

export const encodeAuthenticatedContentTBM: Encoder<AuthenticatedContentTBM> = encode(authenticatedContentTBMEncoder)

export function createMembershipTag(
  membershipKey: Uint8Array,
  tbm: AuthenticatedContentTBM,
  h: Hash,
): Promise<Uint8Array> {
  return h.mac(membershipKey, encode(authenticatedContentTBMEncoder)(tbm))
}

export function verifyMembershipTag(
  membershipKey: Uint8Array,
  tbm: AuthenticatedContentTBM,
  tag: Uint8Array,
  h: Hash,
): Promise<boolean> {
  return h.verifyMac(membershipKey, tag, encode(authenticatedContentTBMEncoder)(tbm))
}

export function makeProposalRef(proposal: AuthenticatedContent, h: Hash): Promise<Uint8Array> {
  return refhash("MLS 1.0 Proposal Reference", encode(authenticatedContentEncoder)(proposal), h)
}
