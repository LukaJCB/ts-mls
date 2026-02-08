import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder, encode } from "./codec/tlsEncoder.js"
import { Hash, refhash } from "./crypto/hash.js"
import {
  framedContentDecoder,
  framedContentAuthDataDecoder,
  framedContentEncoder,
  framedContentAuthDataEncoder,
  framedContentTBSEncoder,
  FramedContent,
  FramedContentAuthData,
  FramedContentCommitData,
  FramedContentData,
  FramedContentProposalData,
  FramedContentTBS,
  FramedContentAuthDataCommit,
  FramedContentCommit,
} from "./framedContent.js"
import { wireformatDecoder, wireformatEncoder, WireformatValue } from "./wireformat.js"

export interface AuthenticatedContent {
  wireformat: WireformatValue
  content: FramedContent
  auth: FramedContentAuthData
}

export type AuthenticatedContentCommit = AuthenticatedContent & {
  content: FramedContentCommit
  auth: FramedContentAuthDataCommit
}

export type AuthenticatedContentProposalOrCommit = AuthenticatedContent & {
  content: (FramedContentProposalData | FramedContentCommitData) & FramedContentData
}

export const authenticatedContentEncoder: Encoder<AuthenticatedContent> = contramapBufferEncoders(
  [wireformatEncoder, framedContentEncoder, framedContentAuthDataEncoder],
  (a) => [a.wireformat, a.content, a.auth] as const,
)

export const authenticatedContentDecoder: Decoder<AuthenticatedContent> = mapDecoders(
  [
    wireformatDecoder,
    flatMapDecoder(framedContentDecoder, (content) => {
      return mapDecoder(framedContentAuthDataDecoder(content.contentType), (auth) => ({ content, auth }))
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

const authenticatedContentTBMEncoder: Encoder<AuthenticatedContentTBM> = contramapBufferEncoders(
  [framedContentTBSEncoder, framedContentAuthDataEncoder],
  (t) => [t.contentTbs, t.auth] as const,
)

export function createMembershipTag(
  membershipKey: Uint8Array,
  tbm: AuthenticatedContentTBM,
  h: Hash,
): Promise<Uint8Array> {
  return h.mac(membershipKey, encode(authenticatedContentTBMEncoder, tbm))
}

export function verifyMembershipTag(
  membershipKey: Uint8Array,
  tbm: AuthenticatedContentTBM,
  tag: Uint8Array,
  h: Hash,
): Promise<boolean> {
  return h.verifyMac(membershipKey, tag, encode(authenticatedContentTBMEncoder, tbm))
}

export function makeProposalRef(proposal: AuthenticatedContent, h: Hash): Promise<Uint8Array> {
  return refhash("MLS 1.0 Proposal Reference", encode(authenticatedContentEncoder, proposal), h)
}
