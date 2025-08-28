import { decodeOptional, encodeOptional } from "./codec/optional.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenType, encodeVarLenType } from "./codec/variableLength.js"
import { decodeProposalOrRef, encodeProposalOrRef, ProposalOrRef } from "./proposalOrRefType.js"
import { decodeUpdatePath, encodeUpdatePath, UpdatePath } from "./updatePath.js"

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
