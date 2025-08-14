import { decodeUint8, encodeUint8 } from "./codec/number"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { decodeProposal, encodeProposal, Proposal } from "./proposal"
import { enumNumberToKey } from "./util/enumHelpers"

const proposalOrRefTypes = {
  proposal: 1,
  reference: 2,
} as const

export type ProposalOrRefTypeName = keyof typeof proposalOrRefTypes
export type ProposalOrRefTypeValue = (typeof proposalOrRefTypes)[ProposalOrRefTypeName]

export const encodeProposalOrRefType: Encoder<ProposalOrRefTypeName> = contramapEncoder(
  encodeUint8,
  (t) => proposalOrRefTypes[t],
)

export const decodeProposalOrRefType: Decoder<ProposalOrRefTypeName> = mapDecoderOption(
  decodeUint8,
  enumNumberToKey(proposalOrRefTypes),
)

export interface ProposalOrRefProposal {
  proposalOrRefType: "proposal"
  proposal: Proposal
}
export interface ProposalOrRefProposalRef {
  proposalOrRefType: "reference"
  reference: Uint8Array
}

export type ProposalOrRef = ProposalOrRefProposal | ProposalOrRefProposalRef

export const encodeProposalOrRefProposal: Encoder<ProposalOrRefProposal> = contramapEncoders(
  [encodeProposalOrRefType, encodeProposal],
  (p) => [p.proposalOrRefType, p.proposal] as const,
)

export const encodeProposalOrRefProposalRef: Encoder<ProposalOrRefProposalRef> = contramapEncoders(
  [encodeProposalOrRefType, encodeVarLenData],
  (r) => [r.proposalOrRefType, r.reference] as const,
)

export const encodeProposalOrRef: Encoder<ProposalOrRef> = (input) => {
  switch (input.proposalOrRefType) {
    case "proposal":
      return encodeProposalOrRefProposal(input)
    case "reference":
      return encodeProposalOrRefProposalRef(input)
  }
}

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
