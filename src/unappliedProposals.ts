import { uint32Decoder, uint32Encoder } from "./codec/number.js"
import { optionalDecoder, optionalEncoder } from "./codec/optional.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { base64RecordEncoder, base64RecordDecoder } from "./codec/variableLength.js"
import { proposalDecoder, Proposal, proposalEncoder } from "./proposal.js"
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

export const proposalWithSenderDecoder: Decoder<ProposalWithSender> = mapDecoders(
  [proposalDecoder, optionalDecoder(uint32Decoder)],
  (proposal, senderLeafIndex) => ({
    proposal,
    senderLeafIndex,
  }),
)

/** @public */
export type UnappliedProposals = Record<string, ProposalWithSender>

export const unappliedProposalsEncoder: BufferEncoder<UnappliedProposals> =
  base64RecordEncoder(proposalWithSenderEncoder)

export const unappliedProposalsDecoder: Decoder<UnappliedProposals> = base64RecordDecoder(proposalWithSenderDecoder)

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
