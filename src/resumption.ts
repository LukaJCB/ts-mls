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
import { AuthenticationService } from "./authenticationService.js"

/** @public */
export async function reinitGroup(
  state: ClientState,
  groupId: Uint8Array,
  version: ProtocolVersionName,
  cipherSuite: CiphersuiteName,
  extensions: GroupContextExtension[],
  authService: AuthenticationService,
  cs: CiphersuiteImpl,
): Promise<CreateCommitResult> {
  const reinitProposal: Proposal = {
    proposalType: defaultProposalTypes.reinit,
    reinit: {
      groupId,
      version: protocolVersions[version],
      cipherSuite: ciphersuites[cipherSuite],
      extensions,
    },
  }

  return createCommit(
    {
      state,
      pskIndex: makePskIndex(state, {}),
      cipherSuite: cs,
      authService,
    },
    {
      extraProposals: [reinitProposal],
    },
  )
}

/** @public */
export async function reinitCreateNewGroup(
  state: ClientState,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  memberKeyPackages: KeyPackage[],
  groupId: Uint8Array,
  cipherSuite: CiphersuiteName,
  extensions: GroupContextExtension[],
  authService: AuthenticationService,
  provider: CryptoProvider = defaultCryptoProvider,
): Promise<CreateCommitResult> {
  const cs = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite), provider)
  const newGroup = await createGroup(groupId, keyPackage, privateKeyPackage, extensions, authService, cs)

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

  return createCommit(
    {
      state: newGroup,
      pskIndex: makePskIndex(state, {}),
      cipherSuite: cs,
      authService,
    },
    {
      extraProposals: [...addProposals, resumptionPsk],
    },
  )
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
export async function branchGroup(
  state: ClientState,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  memberKeyPackages: KeyPackage[],
  newGroupId: Uint8Array,
  authService: AuthenticationService,
  cs: CiphersuiteImpl,
): Promise<CreateCommitResult> {
  const resumptionPsk = makeResumptionPsk(state, resumptionPSKUsages.branch, cs)

  const pskSearch = makePskIndex(state, {})

  const newGroup = await createGroup(
    newGroupId,
    keyPackage,
    privateKeyPackage,
    state.groupContext.extensions,
    authService,
    cs,
  )

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

  return createCommit(
    {
      state: newGroup,
      pskIndex: pskSearch,
      cipherSuite: cs,
      authService,
    },
    {
      extraProposals: [...addMemberProposals, branchPskProposal],
    },
  )
}

/** @public */
export async function joinGroupFromBranch(
  oldState: ClientState,
  welcome: Welcome,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  authService: AuthenticationService,
  ratchetTree: RatchetTree | undefined,
  cs: CiphersuiteImpl,
): Promise<ClientState> {
  const pskSearch = makePskIndex(oldState, {})

  return await joinGroup(welcome, keyPackage, privateKeyPackage, pskSearch, authService, cs, ratchetTree, oldState)
}

/** @public */
export async function joinGroupFromReinit(
  suspendedState: ClientState,
  welcome: Welcome,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  authService: AuthenticationService,
  ratchetTree: RatchetTree | undefined,
  provider: CryptoProvider = defaultCryptoProvider,
): Promise<ClientState> {
  const pskSearch = makePskIndex(suspendedState, {})
  if (suspendedState.groupActiveState.kind !== "suspendedPendingReinit")
    throw new UsageError("Cannot reinit because no init proposal found in last commit")

  const cs = await getCiphersuiteImpl(
    getCiphersuiteFromId(suspendedState.groupActiveState.reinit.cipherSuite),
    provider,
  )

  return await joinGroup(
    welcome,
    keyPackage,
    privateKeyPackage,
    pskSearch,
    authService,
    cs,
    ratchetTree,
    suspendedState,
  )
}
