import { optionalDecoder, optionalEncoder } from "./codec/optional.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder } from "./codec/tlsEncoder.js"
import { varLenTypeDecoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { proposalOrRefDecoder, proposalOrRefEncoder, ProposalOrRef } from "./proposalOrRefType.js"
import { updatePathDecoder, updatePathEncoder, UpdatePath } from "./updatePath.js"

/** @public */
export interface Commit {
  proposals: ProposalOrRef[]
  path: UpdatePath | undefined
}

export const commitEncoder: BufferEncoder<Commit> = contramapBufferEncoders(
  [varLenTypeEncoder(proposalOrRefEncoder), optionalEncoder(updatePathEncoder)],
  (commit) => [commit.proposals, commit.path] as const,
)

export const commitDecoder: Decoder<Commit> = mapDecoders(
  [varLenTypeDecoder(proposalOrRefDecoder), optionalDecoder(updatePathDecoder)],
  (proposals, path) => ({ proposals, path }),
)
