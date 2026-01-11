import { decodeUint32, uint32Encoder } from "./codec/number.js"
import { decodeOptional, optionalEncoder } from "./codec/optional.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { base64RecordEncoder, decodeBase64Record } from "./codec/variableLength.js"
import { decodeProposal, Proposal, proposalEncoder } from "./proposal.js"
import { bytesToBase64 } from "./util/byteArray.js"

/** @public */
export interface ProposalWithSender {
  proposal: Proposal
  senderLeafIndex: number | undefined
}

export const proposalWithSenderEncoder: BufferEncoder<ProposalWithSender> = contramapBufferEncoders(
  [proposalEncoder, optionalEncoder(uint32Encoder)],
  (pws) => [pws.proposal, pws.senderLeafIndex] as const,
)

export const decodeProposalWithSender: Decoder<ProposalWithSender> = mapDecoders(
  [decodeProposal, decodeOptional(decodeUint32)],
  (proposal, senderLeafIndex) => ({
    proposal,
    senderLeafIndex,
  }),
)

/** @public */
export type UnappliedProposals = Record<string, ProposalWithSender>

export const unappliedProposalsEncoder: BufferEncoder<UnappliedProposals> =
  base64RecordEncoder(proposalWithSenderEncoder)

export const decodeUnappliedProposals: Decoder<UnappliedProposals> = decodeBase64Record(decodeProposalWithSender)

export function addUnappliedProposal(
  ref: Uint8Array,
  proposals: UnappliedProposals,
  proposal: Proposal,
  senderLeafIndex: number | undefined,
): UnappliedProposals {
  const r = bytesToBase64(ref)
  return {
    ...proposals,
    [r]: { proposal, senderLeafIndex },
  }
}
