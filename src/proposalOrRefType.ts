import { decodeUint8, encUint8 } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapEnc, contramapEncs, Enc } from "./codec/tlsEncoder.js"
import { decodeVarLenData, encVarLenData } from "./codec/variableLength.js"
import { decodeProposal, encodeProposal, Proposal } from "./proposal.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

const proposalOrRefTypes = {
  proposal: 1,
  reference: 2,
} as const

export type ProposalOrRefTypeName = keyof typeof proposalOrRefTypes
export type ProposalOrRefTypeValue = (typeof proposalOrRefTypes)[ProposalOrRefTypeName]

export const encodeProposalOrRefType: Enc<ProposalOrRefTypeName> = contramapEnc(
  encUint8,
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

export const encodeProposalOrRefProposal: Enc<ProposalOrRefProposal> = contramapEncs(
  [encodeProposalOrRefType, encodeProposal],
  (p) => [p.proposalOrRefType, p.proposal] as const,
)

export const encodeProposalOrRefProposalRef: Enc<ProposalOrRefProposalRef> = contramapEncs(
  [encodeProposalOrRefType, encVarLenData],
  (r) => [r.proposalOrRefType, r.reference] as const,
)

export const encodeProposalOrRef: Enc<ProposalOrRef> = (input) => {
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
