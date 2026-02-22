import { uint8Decoder, uint8Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { proposalDecoder, Proposal, proposalEncoder } from "./proposal.js"
import { numberToEnum } from "./util/enumHelpers.js"

/** @public */
export const proposalOrRefTypes = {
  proposal: 1,
  reference: 2,
} as const

type ProposalOrRefTypeName = keyof typeof proposalOrRefTypes
type ProposalOrRefTypeValue = (typeof proposalOrRefTypes)[ProposalOrRefTypeName]

export const proposalOrRefTypeEncoder: Encoder<ProposalOrRefTypeValue> = uint8Encoder

export const proposalOrRefTypeDecoder: Decoder<ProposalOrRefTypeValue> = mapDecoderOption(
  uint8Decoder,
  numberToEnum(proposalOrRefTypes),
)

/** @public */
export interface ProposalOrRefProposal {
  proposalOrRefType: typeof proposalOrRefTypes.proposal
  proposal: Proposal
}

/** @public */
export interface ProposalOrRefProposalRef {
  proposalOrRefType: typeof proposalOrRefTypes.reference
  reference: Uint8Array
}

/** @public */
export type ProposalOrRef = ProposalOrRefProposal | ProposalOrRefProposalRef

const proposalOrRefProposalEncoder: Encoder<ProposalOrRefProposal> = contramapBufferEncoders(
  [proposalOrRefTypeEncoder, proposalEncoder],
  (p) => [p.proposalOrRefType, p.proposal] as const,
)

const proposalOrRefProposalRefEncoder: Encoder<ProposalOrRefProposalRef> = contramapBufferEncoders(
  [proposalOrRefTypeEncoder, varLenDataEncoder],
  (r) => [r.proposalOrRefType, r.reference] as const,
)

export const proposalOrRefEncoder: Encoder<ProposalOrRef> = (input) => {
  switch (input.proposalOrRefType) {
    case proposalOrRefTypes.proposal:
      return proposalOrRefProposalEncoder(input)
    case proposalOrRefTypes.reference:
      return proposalOrRefProposalRefEncoder(input)
  }
}

export const proposalOrRefDecoder: Decoder<ProposalOrRef> = flatMapDecoder(
  proposalOrRefTypeDecoder,
  (proposalOrRefType): Decoder<ProposalOrRef> => {
    switch (proposalOrRefType) {
      case proposalOrRefTypes.proposal:
        return mapDecoder(proposalDecoder, (proposal) => ({ proposalOrRefType, proposal }))
      case proposalOrRefTypes.reference:
        return mapDecoder(varLenDataDecoder, (reference) => ({ proposalOrRefType, reference }))
    }
  },
)
