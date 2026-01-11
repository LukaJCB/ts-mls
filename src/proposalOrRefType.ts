import { decodeUint8, uint8Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { decodeProposal, Proposal, proposalEncoder } from "./proposal.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

const proposalOrRefTypes = {
  proposal: 1,
  reference: 2,
} as const

export type ProposalOrRefTypeName = keyof typeof proposalOrRefTypes
export type ProposalOrRefTypeValue = (typeof proposalOrRefTypes)[ProposalOrRefTypeName]

export const proposalOrRefTypeEncoder: BufferEncoder<ProposalOrRefTypeName> = contramapBufferEncoder(
  uint8Encoder,
  (t) => proposalOrRefTypes[t],
)

export const encodeProposalOrRefType: Encoder<ProposalOrRefTypeName> = encode(proposalOrRefTypeEncoder)

export const decodeProposalOrRefType: Decoder<ProposalOrRefTypeName> = mapDecoderOption(
  decodeUint8,
  enumNumberToKey(proposalOrRefTypes),
)

/** @public */
export interface ProposalOrRefProposal {
  proposalOrRefType: "proposal"
  proposal: Proposal
}

/** @public */
export interface ProposalOrRefProposalRef {
  proposalOrRefType: "reference"
  reference: Uint8Array
}

/** @public */
export type ProposalOrRef = ProposalOrRefProposal | ProposalOrRefProposalRef

export const proposalOrRefProposalEncoder: BufferEncoder<ProposalOrRefProposal> = contramapBufferEncoders(
  [proposalOrRefTypeEncoder, proposalEncoder],
  (p) => [p.proposalOrRefType, p.proposal] as const,
)

export const encodeProposalOrRefProposal: Encoder<ProposalOrRefProposal> = encode(proposalOrRefProposalEncoder)

export const proposalOrRefProposalRefEncoder: BufferEncoder<ProposalOrRefProposalRef> = contramapBufferEncoders(
  [proposalOrRefTypeEncoder, varLenDataEncoder],
  (r) => [r.proposalOrRefType, r.reference] as const,
)

export const encodeProposalOrRefProposalRef: Encoder<ProposalOrRefProposalRef> = encode(proposalOrRefProposalRefEncoder)

export const proposalOrRefEncoder: BufferEncoder<ProposalOrRef> = (input) => {
  switch (input.proposalOrRefType) {
    case "proposal":
      return proposalOrRefProposalEncoder(input)
    case "reference":
      return proposalOrRefProposalRefEncoder(input)
  }
}

export const encodeProposalOrRef: Encoder<ProposalOrRef> = encode(proposalOrRefEncoder)

export const decodeProposalOrRef: Decoder<ProposalOrRef> = flatMapDecoder(
  decodeProposalOrRefType,
  (proposalOrRefType): Decoder<ProposalOrRef> => {
    switch (proposalOrRefType) {
      case "proposal":
        return mapDecoder(decodeProposal, (proposal) => ({ proposalOrRefType, proposal }))
      case "reference":
        return mapDecoder(decodeVarLenData, (reference) => ({ proposalOrRefType, reference }))
    }
  },
)
