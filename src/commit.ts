import { decodeOptional, optionalEncoder } from "./codec/optional.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder } from "./codec/tlsEncoder.js"
import { decodeVarLenType, varLenTypeEncoder } from "./codec/variableLength.js"
import { decodeProposalOrRef, proposalOrRefEncoder, ProposalOrRef } from "./proposalOrRefType.js"
import { decodeUpdatePath, updatePathEncoder, UpdatePath } from "./updatePath.js"

/** @public */
export interface Commit {
  proposals: ProposalOrRef[]
  path: UpdatePath | undefined
}

export const commitEncoder: BufferEncoder<Commit> = contramapBufferEncoders(
  [varLenTypeEncoder(proposalOrRefEncoder), optionalEncoder(updatePathEncoder)],
  (commit) => [commit.proposals, commit.path] as const,
)

export const decodeCommit: Decoder<Commit> = mapDecoders(
  [decodeVarLenType(decodeProposalOrRef), decodeOptional(decodeUpdatePath)],
  (proposals, path) => ({ proposals, path }),
)
