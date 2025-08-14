import { decodeOptional, encodeOptional } from "./codec/optional"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenType, encodeVarLenType } from "./codec/variableLength"
import { decodeProposalOrRef, encodeProposalOrRef, ProposalOrRef } from "./proposalOrRefType"
import { decodeUpdatePath, encodeUpdatePath, UpdatePath } from "./updatePath"

export interface Commit {
  proposals: ProposalOrRef[]
  path: UpdatePath | undefined
}

export const encodeCommit: Encoder<Commit> = contramapEncoders(
  [encodeVarLenType(encodeProposalOrRef), encodeOptional(encodeUpdatePath)],
  (commit) => [commit.proposals, commit.path] as const,
)

export const decodeCommit: Decoder<Commit> = mapDecoders(
  [decodeVarLenType(decodeProposalOrRef), decodeOptional(decodeUpdatePath)],
  (proposals, path) => ({ proposals, path }),
)
