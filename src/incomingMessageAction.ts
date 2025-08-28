import { ProposalWithSender } from "./unappliedProposals.js"

export type IncomingMessageAction = "accept" | "reject"

export type IncomingMessageCallback = (
  incoming: { kind: "commit"; proposals: ProposalWithSender[] } | { kind: "proposal"; proposal: ProposalWithSender },
) => IncomingMessageAction

export const acceptAll: IncomingMessageCallback = () => "accept"
