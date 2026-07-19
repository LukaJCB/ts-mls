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
  [defaultProposalTypes.add]: { proposal: ProposalAdd }[]
  [defaultProposalTypes.update]: { senderLeafIndex: LeafIndex; proposal: ProposalUpdate }[]
  [defaultProposalTypes.remove]: { proposal: ProposalRemove }[]
  [defaultProposalTypes.psk]: { proposal: ProposalPSK }[]
  [defaultProposalTypes.reinit]: { proposal: ProposalReinit }[]
  [defaultProposalTypes.external_init]: { proposal: ProposalExternalInit }[]
  [defaultProposalTypes.group_context_extensions]: {
    proposal: ProposalGroupContextExtensions
  }[]
}
export function emptyProposals(): GroupedProposals {
  return {
    [defaultProposalTypes.add]: [],
    [defaultProposalTypes.update]: [],
    [defaultProposalTypes.remove]: [],
    [defaultProposalTypes.psk]: [],
    [defaultProposalTypes.reinit]: [],
    [defaultProposalTypes.external_init]: [],
    [defaultProposalTypes.group_context_extensions]: [],
  }
}

export function flattenExtensions(
  groupContextExtensions: { proposal: ProposalGroupContextExtensions }[],
): GroupContextExtension[] | undefined {
  return groupContextExtensions[0]?.proposal.groupContextExtensions.extensions
}
