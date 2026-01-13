import { decodeUint8, uint8Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { decodeProposal, Proposal, proposalEncoder } from "./proposal.js"
import { numberToEnum } from "./util/enumHelpers.js"

export const proposalOrRefTypes = {
  proposal: 1,
  reference: 2,
} as const

export type ProposalOrRefTypeName = keyof typeof proposalOrRefTypes
export type ProposalOrRefTypeValue = (typeof proposalOrRefTypes)[ProposalOrRefTypeName]

export const proposalOrRefTypeEncoder: BufferEncoder<ProposalOrRefTypeValue> = uint8Encoder

export const decodeProposalOrRefType: Decoder<ProposalOrRefTypeValue> = mapDecoderOption(
  decodeUint8,
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

export const proposalOrRefProposalEncoder: BufferEncoder<ProposalOrRefProposal> = contramapBufferEncoders(
  [proposalOrRefTypeEncoder, proposalEncoder],
  (p) => [p.proposalOrRefType, p.proposal] as const,
)

export const proposalOrRefProposalRefEncoder: BufferEncoder<ProposalOrRefProposalRef> = contramapBufferEncoders(
  [proposalOrRefTypeEncoder, varLenDataEncoder],
  (r) => [r.proposalOrRefType, r.reference] as const,
)

export const proposalOrRefEncoder: BufferEncoder<ProposalOrRef> = (input) => {
  switch (input.proposalOrRefType) {
    case proposalOrRefTypes.proposal:
      return proposalOrRefProposalEncoder(input)
    case proposalOrRefTypes.reference:
      return proposalOrRefProposalRefEncoder(input)
  }
}

export const decodeProposalOrRef: Decoder<ProposalOrRef> = flatMapDecoder(
  decodeProposalOrRefType,
  (proposalOrRefType): Decoder<ProposalOrRef> => {
    switch (proposalOrRefType) {
      case proposalOrRefTypes.proposal:
        return mapDecoder(decodeProposal, (proposal) => ({ proposalOrRefType, proposal }))
      case proposalOrRefTypes.reference:
        return mapDecoder(decodeVarLenData, (reference) => ({ proposalOrRefType, reference }))
    }
  },
)
