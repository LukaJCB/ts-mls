import { defaultProposalTypes } from "./defaultProposalType.js"
import { GroupContextExtension } from "./extension.js"
import {
  ProposalAdd,
  ProposalUpdate,
  ProposalRemove,
  ProposalPSK,
  ProposalReinit,
  ProposalExternalInit,
  ProposalGroupContextExtensions,
} from "./proposal.js"
import { LeafIndex } from "./treemath.js"

export interface GroupedProposals {
  [defaultProposalTypes.add]: { senderLeafIndex: LeafIndex | undefined; proposal: ProposalAdd }[]
  [defaultProposalTypes.update]: { senderLeafIndex: LeafIndex; proposal: ProposalUpdate }[]
  [defaultProposalTypes.remove]: { senderLeafIndex: LeafIndex | undefined; proposal: ProposalRemove }[]
  [defaultProposalTypes.psk]: { senderLeafIndex: LeafIndex | undefined; proposal: ProposalPSK }[]
  [defaultProposalTypes.reinit]: { senderLeafIndex: LeafIndex | undefined; proposal: ProposalReinit }[]
  [defaultProposalTypes.external_init]: { senderLeafIndex: LeafIndex | undefined; proposal: ProposalExternalInit }[]
  [defaultProposalTypes.group_context_extensions]: {
    senderLeafIndex: LeafIndex | undefined
    proposal: ProposalGroupContextExtensions
  }[]
}
export const emptyProposals: GroupedProposals = {
  [defaultProposalTypes.add]: [],
  [defaultProposalTypes.update]: [],
  [defaultProposalTypes.remove]: [],
  [defaultProposalTypes.psk]: [],
  [defaultProposalTypes.reinit]: [],
  [defaultProposalTypes.external_init]: [],
  [defaultProposalTypes.group_context_extensions]: [],
}

export function flattenExtensions(
  groupContextExtensions: { proposal: ProposalGroupContextExtensions }[],
): GroupContextExtension[] | undefined {
  return groupContextExtensions[0]?.proposal.groupContextExtensions.extensions
}
