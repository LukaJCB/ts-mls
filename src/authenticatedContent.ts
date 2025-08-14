import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { Hash, refhash } from "./crypto/hash"
import {
  decodeFramedContent,
  decodeFramedContentAuthData,
  encodeFramedContent,
  encodeFramedContentAuthData,
  encodeFramedContentTBS,
  FramedContent,
  FramedContentApplicationData,
  FramedContentAuthData,
  FramedContentCommitData,
  FramedContentData,
  FramedContentProposalData,
  FramedContentTBS,
} from "./framedContent"
import { decodeWireformat, encodeWireformat, WireformatName } from "./wireformat"

export interface AuthenticatedContent {
  wireformat: WireformatName
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
export const encodeAuthenticatedContent: Encoder<AuthenticatedContent> = contramapEncoders(
  [encodeWireformat, encodeFramedContent, encodeFramedContentAuthData],
  (a) => [a.wireformat, a.content, a.auth] as const,
)

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

export const encodeAuthenticatedContentTBM: Encoder<AuthenticatedContentTBM> = contramapEncoders(
  [encodeFramedContentTBS, encodeFramedContentAuthData],
  (t) => [t.contentTbs, t.auth] as const,
)

export function createMembershipTag(
  membershipKey: Uint8Array,
  tbm: AuthenticatedContentTBM,
  h: Hash,
): Promise<Uint8Array> {
  return h.mac(membershipKey, encodeAuthenticatedContentTBM(tbm))
}

export function verifyMembershipTag(
  membershipKey: Uint8Array,
  tbm: AuthenticatedContentTBM,
  tag: Uint8Array,
  h: Hash,
): Promise<boolean> {
  return h.verifyMac(membershipKey, tag, encodeAuthenticatedContentTBM(tbm))
}

export function makeProposalRef(proposal: AuthenticatedContent, h: Hash): Promise<Uint8Array> {
  return refhash("MLS 1.0 Proposal Reference", encodeAuthenticatedContent(proposal), h)
}
