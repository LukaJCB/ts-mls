import { checkCanSendApplicationMessages, ClientState, processProposal } from "./clientState.js"
import { MlsFramedMessage } from "./message.js"
import { protectProposal, protectApplicationData } from "./messageProtection.js"
import { protectProposalPublic } from "./messageProtectionPublic.js"
import { Proposal } from "./proposal.js"
import { addUnappliedProposal } from "./unappliedProposals.js"
import { protocolVersions } from "./protocolVersion.js"
import { wireformats } from "./wireformat.js"
import type { MlsContext } from "./mlsContext.js"
import { defaultClientConfig } from "./clientConfig.js"

/** @public */
export interface CreateMessageResult {
  newState: ClientState
  message: MlsFramedMessage
  consumed: Uint8Array[]
}

/** @public */
export async function createProposal(params: {
  context: MlsContext
  state: ClientState
  wireAsPublicMessage?: boolean
  proposal: Proposal
  authenticatedData?: Uint8Array
}): Promise<CreateMessageResult> {
  const context = params.context
  const state = params.state
  const cs = context.cipherSuite
  const ad = params.authenticatedData ?? new Uint8Array()
  const clientConfig = context.clientConfig ?? defaultClientConfig

  const publicMessage = params.wireAsPublicMessage ?? false
  const proposal = params.proposal

  if (publicMessage) {
    const result = await protectProposalPublic(
      state.signaturePrivateKey,
      state.keySchedule.membershipKey,
      state.groupContext,
      ad,
      proposal,
      state.privatePath.leafIndex,
      cs,
    )
    const newState = await processProposal(
      state,
      {
        content: result.publicMessage.content,
        auth: result.publicMessage.auth,
        wireformat: wireformats.mls_public_message,
      },
      proposal,
      cs.hash,
    )
    return {
      newState,
      message: {
        wireformat: wireformats.mls_public_message,
        version: protocolVersions.mls10,
        publicMessage: result.publicMessage,
      },
      consumed: [],
    }
  } else {
    const result = await protectProposal(
      state.signaturePrivateKey,
      state.keySchedule.senderDataSecret,
      proposal,
      ad,
      state.groupContext,
      state.secretTree,
      state.privatePath.leafIndex,
      clientConfig.paddingConfig,
      cs,
    )

    const newState = {
      ...state,
      secretTree: result.newSecretTree,
      unappliedProposals: addUnappliedProposal(
        result.proposalRef,
        state.unappliedProposals,
        proposal,
        state.privatePath.leafIndex,
      ),
    }

    return {
      newState,
      message: {
        wireformat: wireformats.mls_private_message,
        version: protocolVersions.mls10,
        privateMessage: result.privateMessage,
      },
      consumed: result.consumed,
    }
  }
}

/** @public */
export async function createApplicationMessage(params: {
  context: MlsContext
  state: ClientState
  message: Uint8Array
  authenticatedData?: Uint8Array
}): Promise<CreateMessageResult> {
  const context = params.context
  const state = params.state
  const cs = context.cipherSuite
  const ad = params.authenticatedData ?? new Uint8Array()
  const clientConfig = context.clientConfig ?? defaultClientConfig

  const message = params.message

  checkCanSendApplicationMessages(state)

  const result = await protectApplicationData(
    state.signaturePrivateKey,
    state.keySchedule.senderDataSecret,
    message,
    ad,
    state.groupContext,
    state.secretTree,
    state.privatePath.leafIndex,
    clientConfig.paddingConfig,
    cs,
  )

  return {
    newState: { ...state, secretTree: result.newSecretTree },
    message: {
      version: protocolVersions.mls10,
      wireformat: wireformats.mls_private_message,
      privateMessage: result.privateMessage,
    },
    consumed: result.consumed,
  }
}
