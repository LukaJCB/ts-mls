import { checkCanSendApplicationMessages, ClientState, getOwnLeafNode, saveProposal } from "./clientState.js"
import { LeafNodeTBSUpdate, signLeafNodeUpdate } from "./leafNode.js"
import { leafNodeSources } from "./leafNodeSource.js"
import { MlsFramedMessage } from "./message.js"
import { protectProposal, protectApplicationData } from "./messageProtection.js"
import { protectProposalPublic } from "./messageProtectionPublic.js"
import { Proposal } from "./proposal.js"
import { defaultProposalTypes } from "./defaultProposalType.js"
import { addUnappliedProposal } from "./unappliedProposals.js"
import { protocolVersions } from "./protocolVersion.js"
import { wireformats } from "./wireformat.js"
import type { MlsContext } from "./mlsContext.js"
import { defaultClientConfig } from "./clientConfig.js"
import { InternalError } from "./mlsError.js"
import { LeafNodePatch } from "./leafNodePatch.js"

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
    const newState = await saveProposal(
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
export interface CreateUpdateProposalResult extends CreateMessageResult {
  /**
   * HPKE keypair for the proposer's new leaf. The proposer MUST install the
   * private key into `state.privatePath` (via `updateLeafKey`) only when the
   * commit that applies this proposal is handled, because commits that do not
   * include the proposal leave the proposer's leaf public key unchanged. The
   * public key lets the caller detect which of those two outcomes occurred by
   * comparing it to the post-commit tree's own-leaf public key.
   */
  newLeafKeypair: { hpkePublicKey: Uint8Array; hpkePrivateKey: Uint8Array }
}

/** @public */
export async function createUpdateProposal(params: {
  context: MlsContext
  state: ClientState
  wireAsPublicMessage?: boolean
  authenticatedData?: Uint8Array
  leafNodePatch?: LeafNodePatch
}): Promise<CreateUpdateProposalResult> {
  const { context, state } = params
  const cs = context.cipherSuite
  const ownLeaf = getOwnLeafNode(state)
  if (ownLeaf === undefined) throw new InternalError("No own leaf node found for update proposal")

  const leafSecret = cs.rng.randomBytes(cs.kdf.size)
  const leafKeypair = await cs.hpke.deriveKeyPair(leafSecret)
  const hpkePublicKey = await cs.hpke.exportPublicKey(leafKeypair.publicKey)
  const hpkePrivateKey = await cs.hpke.exportPrivateKey(leafKeypair.privateKey)

  const tbs: LeafNodeTBSUpdate = {
    leafNodeSource: leafNodeSources.update,
    hpkePublicKey,
    signaturePublicKey: params.leafNodePatch?.signatureKeyPair?.publicKey ?? ownLeaf.signaturePublicKey,
    credential: params.leafNodePatch?.credential ?? ownLeaf.credential,
    capabilities: params.leafNodePatch?.capabilities ?? ownLeaf.capabilities,
    extensions: params.leafNodePatch?.extensions ?? ownLeaf.extensions,
    groupId: state.groupContext.groupId,
    leafIndex: state.privatePath.leafIndex,
  }
  const leafNode = await signLeafNodeUpdate(
    tbs,
    params.leafNodePatch?.signatureKeyPair?.signKey ?? state.signaturePrivateKey,
    cs.signature,
  )
  const proposal: Proposal = {
    proposalType: defaultProposalTypes.update,
    update: { leafNode },
  }
  const result = await createProposal({
    context,
    state,
    wireAsPublicMessage: params.wireAsPublicMessage,
    authenticatedData: params.authenticatedData,
    proposal,
  })
  return { ...result, newLeafKeypair: { hpkePublicKey, hpkePrivateKey } }
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
