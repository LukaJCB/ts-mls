import { ClientState, makePskIndex, createGroup, joinGroup } from "./clientState"
import { CreateCommitResult, createCommit } from "./createCommit"
import { CiphersuiteName, CiphersuiteImpl, getCiphersuiteFromName } from "./crypto/ciphersuite"
import { getCiphersuiteImpl } from "./crypto/getCiphersuiteImpl"
import { defaultCryptoProvider } from "./crypto/implementation/default/provider"
import { CryptoProvider } from "./crypto/provider"
import { Extension } from "./extension"
import { KeyPackage, PrivateKeyPackage } from "./keyPackage"
import { UsageError } from "./mlsError"
import { ResumptionPSKUsageName, PreSharedKeyID } from "./presharedkey"
import { Proposal, ProposalAdd, ProposalPSK } from "./proposal"
import { ProtocolVersionName } from "./protocolVersion"
import { RatchetTree } from "./ratchetTree"
import { Welcome } from "./welcome"

export async function reinitGroup(
  state: ClientState,
  groupId: Uint8Array,
  version: ProtocolVersionName,
  cipherSuite: CiphersuiteName,
  extensions: Extension[],
  cs: CiphersuiteImpl,
): Promise<CreateCommitResult> {
  const reinitProposal: Proposal = {
    proposalType: "reinit",
    reinit: {
      groupId,
      version,
      cipherSuite,
      extensions,
    },
  }

  return createCommit(state, makePskIndex(state, {}), false, [reinitProposal], cs)
}

export async function reinitCreateNewGroup(
  state: ClientState,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  memberKeyPackages: KeyPackage[],
  groupId: Uint8Array,
  cipherSuite: CiphersuiteName,
  extensions: Extension[],
  provider: CryptoProvider = defaultCryptoProvider,
): Promise<CreateCommitResult> {
  const cs = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite), provider)
  const newGroup = await createGroup(groupId, keyPackage, privateKeyPackage, extensions, cs)

  const addProposals: Proposal[] = memberKeyPackages.map((kp) => ({
    proposalType: "add",
    add: { keyPackage: kp },
  }))

  const psk = makeResumptionPsk(state, "reinit", cs)

  const resumptionPsk: Proposal = {
    proposalType: "psk",
    psk: {
      preSharedKeyId: psk.id,
    },
  }

  return createCommit(newGroup, makePskIndex(state, {}), false, [...addProposals, resumptionPsk], cs)
}

export function makeResumptionPsk(
  state: ClientState,
  usage: ResumptionPSKUsageName,
  cs: CiphersuiteImpl,
): { id: PreSharedKeyID; secret: Uint8Array } {
  const secret = state.keySchedule.resumptionPsk

  const pskNonce = cs.rng.randomBytes(cs.kdf.size)

  const psk = {
    pskEpoch: state.groupContext.epoch,
    pskGroupId: state.groupContext.groupId,
    psktype: "resumption",
    pskNonce,
    usage,
  } as const

  return { id: psk, secret }
}

export async function branchGroup(
  state: ClientState,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  memberKeyPackages: KeyPackage[],
  newGroupId: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<CreateCommitResult> {
  const resumptionPsk = makeResumptionPsk(state, "branch", cs)

  const pskSearch = makePskIndex(state, {})

  const newGroup = await createGroup(newGroupId, keyPackage, privateKeyPackage, state.groupContext.extensions, cs)

  const addMemberProposals: ProposalAdd[] = memberKeyPackages.map((kp) => ({
    proposalType: "add",
    add: {
      keyPackage: kp,
    },
  }))

  const branchPskProposal: ProposalPSK = {
    proposalType: "psk",
    psk: {
      preSharedKeyId: resumptionPsk.id,
    },
  }

  return createCommit(newGroup, pskSearch, false, [...addMemberProposals, branchPskProposal], cs)
}

export async function joinGroupFromBranch(
  oldState: ClientState,
  welcome: Welcome,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  ratchetTree: RatchetTree | undefined,
  cs: CiphersuiteImpl,
): Promise<ClientState> {
  const pskSearch = makePskIndex(oldState, {})

  return await joinGroup(welcome, keyPackage, privateKeyPackage, pskSearch, cs, ratchetTree, oldState)
}

export async function joinGroupFromReinit(
  suspendedState: ClientState,
  welcome: Welcome,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  ratchetTree: RatchetTree | undefined,
  provider: CryptoProvider = defaultCryptoProvider,
): Promise<ClientState> {
  const pskSearch = makePskIndex(suspendedState, {})
  if (suspendedState.groupActiveState.kind !== "suspendedPendingReinit")
    throw new UsageError("Cannot reinit because no init proposal found in last commit")

  const cs = await getCiphersuiteImpl(
    getCiphersuiteFromName(suspendedState.groupActiveState.reinit.cipherSuite),
    provider,
  )

  return await joinGroup(welcome, keyPackage, privateKeyPackage, pskSearch, cs, ratchetTree, suspendedState)
}
