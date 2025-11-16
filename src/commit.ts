import { decodeOptional, encOptional } from "./codec/optional.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapEncs, Enc } from "./codec/tlsEncoder.js"
import { decodeVarLenType, encVarLenType } from "./codec/variableLength.js"
import { decodeProposalOrRef, encodeProposalOrRef, ProposalOrRef } from "./proposalOrRefType.js"
import { decodeUpdatePath, encodeUpdatePath, UpdatePath } from "./updatePath.js"

export interface Commit {
  proposals: ProposalOrRef[]
  path: UpdatePath | undefined
}

export const encodeCommit: Enc<Commit> = contramapEncs(
  [encVarLenType(encodeProposalOrRef), encOptional(encodeUpdatePath)],
  (commit) => [commit.proposals, commit.path] as const,
)

export const decodeCommit: Decoder<Commit> = mapDecoders(
  [decodeVarLenType(decodeProposalOrRef), decodeOptional(decodeUpdatePath)],
  (proposals, path) => ({ proposals, path }),
)
