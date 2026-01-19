import { ClientState, makePskIndex, createGroup, joinGroup } from "./clientState.js"
import { CreateCommitResult, createCommit } from "./createCommit.js"
import {
  ciphersuites,
  CiphersuiteName,
  CiphersuiteImpl,
  getCiphersuiteFromId,
  getCiphersuiteFromName,
} from "./crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "./crypto/getCiphersuiteImpl.js"
import { defaultCryptoProvider } from "./crypto/implementation/default/provider.js"
import { CryptoProvider } from "./crypto/provider.js"
import { GroupContextExtension } from "./extension.js"
import { KeyPackage, PrivateKeyPackage } from "./keyPackage.js"
import { UsageError } from "./mlsError.js"
import { pskTypes, resumptionPSKUsages, type ResumptionPSKUsageValue, PskId } from "./presharedkey.js"
import { Proposal, ProposalAdd, ProposalPSK } from "./proposal.js"
import { defaultProposalTypes } from "./defaultProposalType.js"
import { protocolVersions, ProtocolVersionName } from "./protocolVersion.js"
import { RatchetTree } from "./ratchetTree.js"
import { Welcome } from "./welcome.js"
import type { MlsContext } from "./mlsContext.js"

/** @public */
export async function reinitGroup(params: {
  context: MlsContext
  state: ClientState
  groupId: Uint8Array
  version: ProtocolVersionName
  cipherSuite: CiphersuiteName
  extensions?: GroupContextExtension[]
}): Promise<CreateCommitResult> {
  const { context, state, groupId, version, cipherSuite, extensions } = params
  const cs = context.cipherSuite
  const authService = context.authService
  const reinitProposal: Proposal = {
    proposalType: defaultProposalTypes.reinit,
    reinit: {
      groupId,
      version: protocolVersions[version],
      cipherSuite: ciphersuites[cipherSuite],
      extensions: extensions ?? [],
    },
  }

  return createCommit({
    context: {
      pskIndex: makePskIndex(state, {}),
      cipherSuite: cs,
      authService,
    },
    state,
    extraProposals: [reinitProposal],
  })
}

/** @public */
export async function reinitCreateNewGroup(params: {
  context: MlsContext
  state: ClientState
  keyPackage: KeyPackage
  privateKeyPackage: PrivateKeyPackage
  memberKeyPackages: KeyPackage[]
  groupId: Uint8Array
  cipherSuite: CiphersuiteName
  extensions?: GroupContextExtension[]
  provider?: CryptoProvider
}): Promise<CreateCommitResult> {
  const {
    context,
    state,
    keyPackage,
    privateKeyPackage,
    memberKeyPackages,
    groupId,
    cipherSuite,
    extensions,
    provider,
  } = params
  const authService = context.authService
  const cs = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite), provider ?? defaultCryptoProvider)
  const newGroup = await createGroup({
    context: { cipherSuite: cs, authService: context.authService },
    groupId,
    keyPackage,
    privateKeyPackage,
    extensions,
  })

  const addProposals: Proposal[] = memberKeyPackages.map((kp) => ({
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: kp },
  }))

  const psk = makeResumptionPsk(state, resumptionPSKUsages.reinit, cs)

  const resumptionPsk: Proposal = {
    proposalType: defaultProposalTypes.psk,
    psk: {
      preSharedKeyId: psk.id,
    },
  }

  return createCommit({
    context: {
      pskIndex: makePskIndex(state, {}),
      cipherSuite: cs,
      authService,
    },
    state: newGroup,
    extraProposals: [...addProposals, resumptionPsk],
  })
}

export function makeResumptionPsk(
  state: ClientState,
  usage: ResumptionPSKUsageValue,
  cs: CiphersuiteImpl,
): { id: PskId; secret: Uint8Array } {
  const secret = state.keySchedule.resumptionPsk

  const pskNonce = cs.rng.randomBytes(cs.kdf.size)

  const psk = {
    pskEpoch: state.groupContext.epoch,
    pskGroupId: state.groupContext.groupId,
    psktype: pskTypes.resumption,
    pskNonce,
    usage,
  } as const

  return { id: psk, secret }
}

/** @public */
export async function branchGroup(params: {
  context: MlsContext
  state: ClientState
  keyPackage: KeyPackage
  privateKeyPackage: PrivateKeyPackage
  memberKeyPackages: KeyPackage[]
  newGroupId: Uint8Array
}): Promise<CreateCommitResult> {
  const { context, state, keyPackage, privateKeyPackage, memberKeyPackages, newGroupId } = params
  const cs = context.cipherSuite
  const authService = context.authService
  const resumptionPsk = makeResumptionPsk(state, resumptionPSKUsages.branch, cs)

  const pskSearch = makePskIndex(state, {})

  const newGroup = await createGroup({
    context: { cipherSuite: cs, authService },
    groupId: newGroupId,
    keyPackage,
    privateKeyPackage,
    extensions: state.groupContext.extensions,
  })

  const addMemberProposals: ProposalAdd[] = memberKeyPackages.map((kp) => ({
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: kp,
    },
  }))

  const branchPskProposal: ProposalPSK = {
    proposalType: defaultProposalTypes.psk,
    psk: {
      preSharedKeyId: resumptionPsk.id,
    },
  }

  return createCommit({
    context: {
      pskIndex: pskSearch,
      cipherSuite: cs,
      authService,
    },
    state: newGroup,
    extraProposals: [...addMemberProposals, branchPskProposal],
  })
}

/** @public */
export async function joinGroupFromBranch(params: {
  context: MlsContext
  oldState: ClientState
  welcome: Welcome
  keyPackage: KeyPackage
  privateKeyPackage: PrivateKeyPackage
  ratchetTree?: RatchetTree
}): Promise<ClientState> {
  const context = params.context
  const oldState = params.oldState
  const pskSearch = makePskIndex(oldState, {})

  return await joinGroup({
    context: { ...context, pskIndex: pskSearch },
    welcome: params.welcome,
    keyPackage: params.keyPackage,
    privateKeys: params.privateKeyPackage,
    ratchetTree: params.ratchetTree,
    resumingFromState: oldState,
  })
}

/** @public */
export async function joinGroupFromReinit(params: {
  context: MlsContext
  suspendedState: ClientState
  welcome: Welcome
  keyPackage: KeyPackage
  privateKeyPackage: PrivateKeyPackage
  ratchetTree?: RatchetTree
  provider?: CryptoProvider
}): Promise<ClientState> {
  const context = params.context
  const suspendedState = params.suspendedState
  const pskSearch = makePskIndex(suspendedState, {})
  if (suspendedState.groupActiveState.kind !== "suspendedPendingReinit")
    throw new UsageError("Cannot reinit because no init proposal found in last commit")

  const cs = await getCiphersuiteImpl(
    getCiphersuiteFromId(suspendedState.groupActiveState.reinit.cipherSuite),
    params.provider ?? defaultCryptoProvider,
  )

  return await joinGroup({
    context: { ...context, cipherSuite: cs, pskIndex: pskSearch },
    welcome: params.welcome,
    keyPackage: params.keyPackage,
    privateKeys: params.privateKeyPackage,
    ratchetTree: params.ratchetTree,
    resumingFromState: suspendedState,
  })
}
