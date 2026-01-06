import { ProposalWithSender } from "./unappliedProposals.js"
import type { LeafIndex } from "./treemath.js"

export type IncomingMessageAction = "accept" | "reject"

export type IncomingMessageCallback = (
  incoming:
    | { kind: "commit"; senderLeafIndex: LeafIndex | undefined; proposals: ProposalWithSender[] }
    | { kind: "proposal"; proposal: ProposalWithSender },
) => IncomingMessageAction

export const acceptAll: IncomingMessageCallback = () => "accept"
