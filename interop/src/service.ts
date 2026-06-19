import {
  ciphersuites,
  createGroup,
  joinGroup,
  createCommit,
  createProposal,
  createUpdateProposal,
  updateLeafKey,
  createApplicationMessage,
  processMessage,
  generateKeyPackage,
  getCiphersuiteImpl,
  mlsExporter,
  defaultCredentialTypes,
  defaultProposalTypes,
  defaultExtensionTypes,
  getOwnLeafNode,
  isDefaultCredential,
  isDefaultExtension,
  unsafeTestingAuthenticationService,
  encode,
  decode,
  bytesToBase64,
  mlsMessageEncoder,
  createGroupInfoWithExternalPub,
  createGroupInfoWithExternalPubAndRatchetTree,
  joinGroupExternal,
  branchGroup,
  joinGroupFromBranch,
  reinitCreateNewGroup,
  joinGroupFromReinit,
  proposeAddExternal,
  proposeExternal,
  protocolVersions,
  wireformats,
  type Proposal,
  type ProposalAdd,
  type ProposalRemove,
  type ProposalPSK,
  type ProposalGroupContextExtensions,
  type ProposalReinit,
  type GroupContextExtension,
  type Credential,
  type MlsContext,
  type MlsFramedMessage,
  type ClientState,
  type ExternalSender,
  senderTypes,
} from "../../src/index.js"
import { ratchetTreeEncoder, ratchetTreeDecoder } from "../../src/ratchetTree.js"
import { externalSenderEncoder, externalSenderDecoder } from "../../src/externalSender.js"
import { decryptSenderData } from "../../src/privateMessage.js"
import type * as grpc from "@grpc/grpc-js"
import { status as grpcStatus } from "@grpc/grpc-js"
import { Store, type GroupEntry } from "./state.js"
import {
  ciphersuiteNameFromId,
  decodeFramedMessage,
  decodeKeyPackageMessage,
  decodeWelcomeMessage,
  decodeGroupInfo,
  leafIndexForIdentity,
  leafIndexForIdentityInTree,
  toGroupContextExtension,
  externalPskId,
  resumptionPskId,
  pskStoreKey,
  type ProtoExtension,
} from "./conversions.js"
import { ratchetTreeFromExtension } from "../../src/groupInfo.js"
import type { RatchetTree } from "../../src/ratchetTree.js"

const INTEROP_CIPHERSUITES = [
  ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
  ciphersuites.MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
  ciphersuites.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
  ciphersuites.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
  ciphersuites.MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
  ciphersuites.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
  ciphersuites.MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
]

const toBytes = (v: unknown): Uint8Array => {
  if (v instanceof Uint8Array) return v
  if (Buffer.isBuffer(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength)
  if (Array.isArray(v)) return Uint8Array.from(v as number[])
  if (v === undefined || v === null) return new Uint8Array()
  throw new Error(`Expected bytes, got ${typeof v}`)
}

const toStr = (v: unknown): string => (typeof v === "string" ? v : new TextDecoder().decode(toBytes(v)))

const basicCredential = (identity: Uint8Array): Credential => ({
  credentialType: defaultCredentialTypes.basic,
  identity,
})

const mlsContext = (store: Store, entry: GroupEntry): MlsContext => ({
  cipherSuite: entry.cipherSuite,
  authService: unsafeTestingAuthenticationService,
  externalPsks: Object.fromEntries(store.psks),
})

function wrap<Req, Res>(fn: (req: Req) => Promise<Res>): grpc.handleUnaryCall<Req, Res> {
  return (call, callback) => {
    fn(call.request)
      .then((res) => callback(null, res))
      .catch((err: unknown) => {
        const message = err instanceof Error ? `${err.name}: ${err.message}` : String(err)
        const stack = err instanceof Error && err.stack ? err.stack : ""
        console.error(`[rpc error] ${message}\n${stack}`)
        callback({ code: grpcStatus.INTERNAL, details: message, name: "MLSError", message })
      })
  }
}

async function tryIngest(store: Store, entry: GroupEntry, bytes: Uint8Array): Promise<GroupEntry> {
  const key = bytesToBase64(bytes)
  if (entry.ingestedBytes.has(key)) return entry
  try {
    const framed = decodeFramedMessage(bytes)
    if (await isOwnMemberMessage(framed, entry)) {
      entry.ingestedBytes.add(key)
      return entry
    }
    const result = await processMessage({ context: mlsContext(store, entry), state: entry.state, message: framed })
    entry.ingestedBytes.add(key)
    if (result.kind === "newState") return { ...entry, state: result.newState }
    return entry
  } catch (e) {
    const err = e as Error
    console.error(`[tryIngest] FAILED: ${err.message}\n${err.stack ?? ""}`)
    return entry
  }
}

async function isOwnMemberMessage(framed: MlsFramedMessage, entry: GroupEntry): Promise<boolean> {
  const ownLeaf = entry.state.privatePath.leafIndex
  if (framed.wireformat === wireformats.mls_public_message) {
    const sender = framed.publicMessage.content.sender
    return sender.senderType === senderTypes.member && sender.leafIndex === ownLeaf
  }
  const senderData = await decryptSenderData(
    framed.privateMessage,
    entry.state.keySchedule.senderDataSecret,
    entry.cipherSuite,
  )
  return senderData !== undefined && senderData.leafIndex === ownLeaf
}

export function makeService(store: Store): grpc.UntypedServiceImplementation {
  const handlers: grpc.UntypedServiceImplementation = {
    Name: wrap(async () => ({ name: "ts-mls" })),
    SupportedCiphersuites: wrap(async () => ({ ciphersuites: INTEROP_CIPHERSUITES })),

    CreateGroup: wrap(
      async (req: { group_id: unknown; cipher_suite: number; encrypt_handshake: boolean; identity: unknown }) => {
        const cipherSuite = await getCiphersuiteImpl(ciphersuiteNameFromId(req.cipher_suite))
        const keyPkg = await generateKeyPackage({ credential: basicCredential(toBytes(req.identity)), cipherSuite })
        const state = await createGroup({
          context: { cipherSuite, authService: unsafeTestingAuthenticationService },
          groupId: toBytes(req.group_id),
          keyPackage: keyPkg.publicPackage,
          privateKeyPackage: keyPkg.privatePackage,
        })
        const state_id = store.insertGroup({ state, cipherSuite, wireAsPublicMessage: !req.encrypt_handshake })
        return { state_id }
      },
    ),

    CreateKeyPackage: wrap(async (req: { cipher_suite: number; identity: unknown }) => {
      const cipherSuite = await getCiphersuiteImpl(ciphersuiteNameFromId(req.cipher_suite))
      const { publicPackage, privatePackage } = await generateKeyPackage({
        credential: basicCredential(toBytes(req.identity)),
        cipherSuite,
      })
      const transaction_id = store.insertKeyPackage({ publicPackage, privatePackage, cipherSuite })
      return {
        transaction_id,
        key_package: encode(mlsMessageEncoder, {
          version: protocolVersions.mls10,
          wireformat: wireformats.mls_key_package,
          keyPackage: publicPackage,
        }),
        init_priv: privatePackage.initPrivateKey,
        encryption_priv: privatePackage.hpkePrivateKey,
        signature_priv: privatePackage.signaturePrivateKey,
      }
    }),

    JoinGroup: wrap(
      async (req: {
        transaction_id: number
        welcome: unknown
        encrypt_handshake: boolean
        identity: unknown
        ratchet_tree: unknown
      }) => {
        const kpEntry = store.takeKeyPackage(req.transaction_id)
        const welcome = decodeWelcomeMessage(toBytes(req.welcome))
        const rtBytes = toBytes(req.ratchet_tree)
        const ratchetTree = rtBytes.length > 0 ? decodeRatchetTree(rtBytes) : undefined
        const state = await joinGroup({
          context: {
            cipherSuite: kpEntry.cipherSuite,
            authService: unsafeTestingAuthenticationService,
            externalPsks: Object.fromEntries(store.psks),
          },
          welcome,
          keyPackage: kpEntry.publicPackage,
          privateKeys: kpEntry.privatePackage,
          ratchetTree,
        })
        const state_id = store.insertGroup({
          state,
          cipherSuite: kpEntry.cipherSuite,
          wireAsPublicMessage: !req.encrypt_handshake,
        })
        return { state_id, epoch_authenticator: state.keySchedule.epochAuthenticator }
      },
    ),

    StateAuth: wrap(async (req: { state_id: number }) => {
      const entry = store.getGroup(req.state_id)
      return { state_auth_secret: entry.state.keySchedule.epochAuthenticator }
    }),

    Export: wrap(async (req: { state_id: number; label: string; context: unknown; key_length: number }) => {
      const entry = store.getGroup(req.state_id)
      const secret = await mlsExporter(
        entry.state.keySchedule.exporterSecret,
        req.label,
        toBytes(req.context),
        req.key_length,
        entry.cipherSuite,
      )
      return { exported_secret: secret }
    }),

    Protect: wrap(async (req: { state_id: number; authenticated_data: unknown; plaintext: unknown }) => {
      const entry = store.getGroup(req.state_id)
      const result = await createApplicationMessage({
        context: mlsContext(store, entry),
        state: entry.state,
        message: toBytes(req.plaintext),
        authenticatedData: toBytes(req.authenticated_data),
      })
      store.updateGroup(req.state_id, { state: result.newState })
      return { ciphertext: encode(mlsMessageEncoder, result.message) }
    }),

    Unprotect: wrap(async (req: { state_id: number; ciphertext: unknown }) => {
      const entry = store.getGroup(req.state_id)
      const framed = decodeFramedMessage(toBytes(req.ciphertext))
      const result = await processMessage({ context: mlsContext(store, entry), state: entry.state, message: framed })
      if (result.kind !== "applicationMessage") throw new Error(`Expected application message, got ${result.kind}`)
      store.updateGroup(req.state_id, { state: result.newState })
      return { authenticated_data: result.aad, plaintext: result.message }
    }),

    StorePSK: wrap(async (req: { state_or_transaction_id: number; psk_id: unknown; psk_secret: unknown }) => {
      // PSKs are stored in the shared map keyed by base64(psk_id). The
      // state_or_transaction_id parameter is advisory — ts-mls does not
      // partition PSKs per group/transaction.
      store.psks.set(pskStoreKey(toBytes(req.psk_id)), toBytes(req.psk_secret))
      return {}
    }),

    AddProposal: wrap(async (req: { state_id: number; key_package: unknown }) => {
      const entry = store.getGroup(req.state_id)
      const keyPackage = decodeKeyPackageMessage(toBytes(req.key_package))
      const proposal: ProposalAdd = { proposalType: defaultProposalTypes.add, add: { keyPackage } }
      return makeProposal(store, req.state_id, entry, proposal)
    }),

    UpdateProposal: wrap(async (req: { state_id: number }) => {
      const entry = store.getGroup(req.state_id)
      const result = await createUpdateProposal({
        context: mlsContext(store, entry),
        state: entry.state,
        wireAsPublicMessage: entry.wireAsPublicMessage,
      })
      store.updateGroup(req.state_id, {
        state: result.newState,
        pendingLeafUpdate: result.newLeafKeypair,
      })
      return { proposal: encode(mlsMessageEncoder, result.message) }
    }),

    RemoveProposal: wrap(async (req: { state_id: number; removed_id: unknown }) => {
      const entry = store.getGroup(req.state_id)
      const leafIndex = leafIndexForIdentity(entry.state, toBytes(req.removed_id))
      const proposal: ProposalRemove = { proposalType: defaultProposalTypes.remove, remove: { removed: leafIndex } }
      return makeProposal(store, req.state_id, entry, proposal)
    }),

    ExternalPSKProposal: wrap(async (req: { state_id: number; psk_id: unknown }) => {
      const entry = store.getGroup(req.state_id)
      const pskId = externalPskId(toBytes(req.psk_id), entry.cipherSuite.kdf.size, entry.cipherSuite.rng)
      const proposal: ProposalPSK = { proposalType: defaultProposalTypes.psk, psk: { preSharedKeyId: pskId } }
      return makeProposal(store, req.state_id, entry, proposal)
    }),

    ResumptionPSKProposal: wrap(async (req: { state_id: number; epoch_id: number | string | bigint }) => {
      const entry = store.getGroup(req.state_id)
      const epoch = typeof req.epoch_id === "bigint" ? req.epoch_id : BigInt(req.epoch_id)
      const pskId = resumptionPskId(entry.state, epoch, entry.cipherSuite.kdf.size, entry.cipherSuite.rng)
      const proposal: ProposalPSK = { proposalType: defaultProposalTypes.psk, psk: { preSharedKeyId: pskId } }
      return makeProposal(store, req.state_id, entry, proposal)
    }),

    GroupContextExtensionsProposal: wrap(async (req: { state_id: number; extensions: ProtoExtension[] }) => {
      const entry = store.getGroup(req.state_id)
      const extensions: GroupContextExtension[] = (req.extensions ?? []).map(toGroupContextExtension)
      const proposal: ProposalGroupContextExtensions = {
        proposalType: defaultProposalTypes.group_context_extensions,
        groupContextExtensions: { extensions },
      }
      return makeProposal(store, req.state_id, entry, proposal)
    }),

    Commit: wrap(
      async (req: {
        state_id: number
        by_reference: unknown[]
        by_value: unknown[]
        force_path: boolean
        external_tree: boolean
      }) => {
        let entry = store.getGroup(req.state_id)
        for (const ref of req.by_reference ?? []) entry = await tryIngest(store, entry, toBytes(ref))
        const extraProposals = (req.by_value ?? [])
          .map((raw) => materializeByValueProposal(raw, entry))
          .filter((p): p is Proposal => !!p)
        const result = await createCommit({
          context: mlsContext(store, entry),
          state: entry.state,
          extraProposals,
          ratchetTreeExtension: true,
          wireAsPublicMessage: entry.wireAsPublicMessage,
        })
        store.updateGroup(req.state_id, { state: entry.state, pendingNewState: result.newState })
        const commit = encode(mlsMessageEncoder, result.commit)
        const welcome = result.welcome ? encode(mlsMessageEncoder, result.welcome) : new Uint8Array()
        const ratchet_tree = req.external_tree ? encodeRatchetTree(result.newState) : new Uint8Array()
        return { commit, welcome, ratchet_tree }
      },
    ),

    HandleCommit: wrap(async (req: { state_id: number; proposal: unknown[]; commit: unknown }) => {
      let entry = store.getGroup(req.state_id)
      for (const p of req.proposal ?? []) entry = await tryIngest(store, entry, toBytes(p))
      const commit = decodeFramedMessage(toBytes(req.commit))
      const result = await processCommitWithPendingLeaf(entry, commit, mlsContext(store, entry))
      if (result.kind !== "newState") throw new Error(`Expected state transition, got ${result.kind}`)
      const settled = applyPendingLeafUpdate(entry, result.newState)
      store.updateGroup(req.state_id, {
        state: settled.state,
        pendingNewState: undefined,
        pendingLeafUpdate: settled.pending,
      })
      return { state_id: req.state_id, epoch_authenticator: settled.state.keySchedule.epochAuthenticator }
    }),

    HandlePendingCommit: wrap(async (req: { state_id: number }) => {
      const entry = store.getGroup(req.state_id)
      if (!entry.pendingNewState) throw new Error("No pending commit to apply")
      const settled = applyPendingLeafUpdate(entry, entry.pendingNewState)
      store.updateGroup(req.state_id, {
        state: settled.state,
        pendingNewState: undefined,
        pendingLeafUpdate: settled.pending,
      })
      return { state_id: req.state_id, epoch_authenticator: settled.state.keySchedule.epochAuthenticator }
    }),

    Free: wrap(async (req: { state_id: number }) => {
      store.deleteGroup(req.state_id)
      return {}
    }),

    GroupInfo: wrap(async (req: { state_id: number; external_tree: boolean }) => {
      const entry = store.getGroup(req.state_id)
      const gi = req.external_tree
        ? await createGroupInfoWithExternalPub(entry.state, [], entry.cipherSuite)
        : await createGroupInfoWithExternalPubAndRatchetTree(entry.state, [], entry.cipherSuite)
      const ratchet_tree = req.external_tree ? encodeRatchetTree(entry.state) : new Uint8Array()
      const group_info = encode(mlsMessageEncoder, {
        version: protocolVersions.mls10,
        wireformat: wireformats.mls_group_info,
        groupInfo: gi,
      })
      return { group_info, ratchet_tree }
    }),

    ExternalJoin: wrap(
      async (req: {
        group_info: unknown
        ratchet_tree: unknown
        encrypt_handshake: boolean
        identity: unknown
        remove_prior: boolean
        psks: { psk_id: unknown; psk_secret: unknown }[]
      }) => {
        const groupInfo = decodeGroupInfo(toBytes(req.group_info))
        const cipherSuite = await getCiphersuiteImpl(ciphersuiteNameFromId(groupInfo.groupContext.cipherSuite))
        for (const p of req.psks ?? []) store.psks.set(pskStoreKey(toBytes(p.psk_id)), toBytes(p.psk_secret))
        const keyPkg = await generateKeyPackage({ credential: basicCredential(toBytes(req.identity)), cipherSuite })
        const rtBytes = toBytes(req.ratchet_tree)
        const tree = rtBytes.length > 0 ? decodeRatchetTree(rtBytes) : undefined
        const result = await joinGroupExternal({
          context: {
            cipherSuite,
            authService: unsafeTestingAuthenticationService,
            externalPsks: Object.fromEntries(store.psks),
          },
          groupInfo,
          keyPackage: keyPkg.publicPackage,
          privateKeys: keyPkg.privatePackage,
          resync: !!req.remove_prior,
          tree,
        })
        const state_id = store.insertGroup({
          state: result.newState,
          cipherSuite,
          wireAsPublicMessage: !req.encrypt_handshake,
        })
        return {
          state_id,
          commit: encode(mlsMessageEncoder, result.commit),
          epoch_authenticator: result.newState.keySchedule.epochAuthenticator,
        }
      },
    ),

    CreateBranch: wrap(
      async (req: {
        state_id: number
        group_id: unknown
        extensions: ProtoExtension[]
        key_packages: unknown[]
        force_path: boolean
        external_tree: boolean
      }) => {
        const entry = store.getGroup(req.state_id)
        const keyPkg = await generateKeyPackage({
          credential: basicCredential(getOwnIdentity(entry.state) ?? new Uint8Array()),
          cipherSuite: entry.cipherSuite,
        })
        const memberKeyPackages = (req.key_packages ?? []).map((kp) => decodeKeyPackageMessage(toBytes(kp)))
        const result = await branchGroup({
          context: mlsContext(store, entry),
          state: entry.state,
          keyPackage: keyPkg.publicPackage,
          privateKeyPackage: keyPkg.privatePackage,
          memberKeyPackages,
          newGroupId: toBytes(req.group_id),
          ratchetTreeExtension: !req.external_tree,
          wireAsPublicMessage: entry.wireAsPublicMessage,
        })
        const newStateId = store.insertGroup({
          state: result.newState,
          cipherSuite: entry.cipherSuite,
          wireAsPublicMessage: entry.wireAsPublicMessage,
        })
        const welcome = result.welcome ? encode(mlsMessageEncoder, result.welcome) : new Uint8Array()
        const ratchet_tree = req.external_tree ? encodeRatchetTree(result.newState) : new Uint8Array()
        return {
          state_id: newStateId,
          welcome,
          ratchet_tree,
          epoch_authenticator: result.newState.keySchedule.epochAuthenticator,
        }
      },
    ),

    HandleBranch: wrap(
      async (req: { state_id: number; transaction_id: number; welcome: unknown; ratchet_tree: unknown }) => {
        const oldEntry = store.getGroup(req.state_id)
        const kpEntry = store.takeKeyPackage(req.transaction_id)
        const welcome = decodeWelcomeMessage(toBytes(req.welcome))
        const rtBytes = toBytes(req.ratchet_tree)
        const tree = rtBytes.length > 0 ? decodeRatchetTree(rtBytes) : undefined
        const newState = await joinGroupFromBranch({
          context: {
            cipherSuite: kpEntry.cipherSuite,
            authService: unsafeTestingAuthenticationService,
            externalPsks: Object.fromEntries(store.psks),
          },
          oldState: oldEntry.state,
          welcome,
          keyPackage: kpEntry.publicPackage,
          privateKeyPackage: kpEntry.privatePackage,
          ratchetTree: tree,
        })
        const newStateId = store.insertGroup({
          state: newState,
          cipherSuite: kpEntry.cipherSuite,
          wireAsPublicMessage: oldEntry.wireAsPublicMessage,
        })
        return { state_id: newStateId, epoch_authenticator: newState.keySchedule.epochAuthenticator }
      },
    ),

    ReInitProposal: wrap(
      async (req: { state_id: number; cipher_suite: number; group_id: unknown; extensions: ProtoExtension[] }) => {
        const entry = store.getGroup(req.state_id)
        const extensions = (req.extensions ?? []).map(toGroupContextExtension)
        const proposal: ProposalReinit = {
          proposalType: defaultProposalTypes.reinit,
          reinit: {
            groupId: toBytes(req.group_id),
            version: protocolVersions.mls10,
            cipherSuite: req.cipher_suite,
            extensions,
          },
        }
        return makeProposal(store, req.state_id, entry, proposal)
      },
    ),

    ReInitCommit: wrap(
      async (req: {
        state_id: number
        by_reference: unknown[]
        by_value: unknown[]
        force_path: boolean
        external_tree: boolean
      }) => {
        // Same as Commit; reinit proposal is delivered via by_reference/by_value.
        let entry = store.getGroup(req.state_id)
        for (const ref of req.by_reference ?? []) entry = await tryIngest(store, entry, toBytes(ref))
        const extraProposals = (req.by_value ?? [])
          .map((raw) => materializeByValueProposal(raw, entry))
          .filter((p): p is Proposal => !!p)
        const result = await createCommit({
          context: mlsContext(store, entry),
          state: entry.state,
          extraProposals,
          ratchetTreeExtension: true,
          wireAsPublicMessage: entry.wireAsPublicMessage,
        })
        store.updateGroup(req.state_id, { state: entry.state, pendingNewState: result.newState })
        return {
          commit: encode(mlsMessageEncoder, result.commit),
          welcome: new Uint8Array(),
          ratchet_tree: req.external_tree ? encodeRatchetTree(result.newState) : new Uint8Array(),
        }
      },
    ),

    HandlePendingReInitCommit: wrap(async (req: { state_id: number }) => {
      const entry = store.getGroup(req.state_id)
      if (!entry.pendingNewState) throw new Error("No pending reinit commit")
      const suspended = entry.pendingNewState
      if (suspended.groupActiveState.kind !== "suspendedPendingReinit")
        throw new Error(`Expected suspendedPendingReinit, got ${suspended.groupActiveState.kind}`)
      return finishReInit(store, req.state_id, entry, suspended)
    }),

    HandleReInitCommit: wrap(async (req: { state_id: number; proposal: unknown[]; commit: unknown }) => {
      let entry = store.getGroup(req.state_id)
      for (const p of req.proposal ?? []) entry = await tryIngest(store, entry, toBytes(p))
      const commit = decodeFramedMessage(toBytes(req.commit))
      const result = await processMessage({ context: mlsContext(store, entry), state: entry.state, message: commit })
      if (result.kind !== "newState") throw new Error(`Expected newState, got ${result.kind}`)
      if (result.newState.groupActiveState.kind !== "suspendedPendingReinit")
        throw new Error("commit did not yield suspendedPendingReinit state")
      return finishReInit(store, req.state_id, entry, result.newState)
    }),

    ReInitWelcome: wrap(
      async (req: { reinit_id: number; key_package: unknown[]; force_path: boolean; external_tree: boolean }) => {
        const reinit = store.getReinit(req.reinit_id)
        if (!reinit.newKey) throw new Error("Reinit has no new-suite key package")
        if (reinit.suspendedState.groupActiveState.kind !== "suspendedPendingReinit")
          throw new Error("Reinit state not suspended")
        const newCsName = ciphersuiteNameFromId(reinit.suspendedState.groupActiveState.reinit.cipherSuite)
        const newCs = await getCiphersuiteImpl(newCsName)
        const memberKeyPackages = (req.key_package ?? []).map((kp) => decodeKeyPackageMessage(toBytes(kp)))
        const result = await reinitCreateNewGroup({
          context: {
            cipherSuite: reinit.cipherSuite,
            authService: unsafeTestingAuthenticationService,
            externalPsks: Object.fromEntries(store.psks),
          },
          state: reinit.suspendedState,
          keyPackage: reinit.newKey.publicPackage,
          privateKeyPackage: reinit.newKey.privatePackage,
          memberKeyPackages,
          groupId: reinit.suspendedState.groupActiveState.reinit.groupId,
          cipherSuite: newCsName,
          extensions: reinit.suspendedState.groupActiveState.reinit.extensions,
          ratchetTreeExtension: !req.external_tree,
          wireAsPublicMessage: reinit.wireAsPublicMessage,
        })
        const newStateId = store.insertGroup({
          state: result.newState,
          cipherSuite: newCs,
          wireAsPublicMessage: reinit.wireAsPublicMessage,
        })
        store.updateReinit(req.reinit_id, { createdStateId: newStateId })
        const welcome = result.welcome ? encode(mlsMessageEncoder, result.welcome) : new Uint8Array()
        return {
          state_id: newStateId,
          welcome,
          ratchet_tree: req.external_tree ? encodeRatchetTree(result.newState) : new Uint8Array(),
          epoch_authenticator: result.newState.keySchedule.epochAuthenticator,
        }
      },
    ),

    HandleReInitWelcome: wrap(async (req: { reinit_id: number; welcome: unknown; ratchet_tree: unknown }) => {
      const reinit = store.getReinit(req.reinit_id)
      if (!reinit.newKey) throw new Error("Reinit has no new-suite key package")
      const welcome = decodeWelcomeMessage(toBytes(req.welcome))
      const rtBytes = toBytes(req.ratchet_tree)
      const tree = rtBytes.length > 0 ? decodeRatchetTree(rtBytes) : undefined
      if (reinit.suspendedState.groupActiveState.kind !== "suspendedPendingReinit")
        throw new Error("Reinit state not suspended")
      const newCsName = ciphersuiteNameFromId(reinit.suspendedState.groupActiveState.reinit.cipherSuite)
      const newCs = await getCiphersuiteImpl(newCsName)
      const newState = await joinGroupFromReinit({
        context: {
          cipherSuite: newCs,
          authService: unsafeTestingAuthenticationService,
          externalPsks: Object.fromEntries(store.psks),
        },
        suspendedState: reinit.suspendedState,
        welcome,
        keyPackage: reinit.newKey.publicPackage,
        privateKeyPackage: reinit.newKey.privatePackage,
        ratchetTree: tree,
      })
      const state_id = store.insertGroup({
        state: newState,
        cipherSuite: newCs,
        wireAsPublicMessage: reinit.wireAsPublicMessage,
      })
      return { state_id, epoch_authenticator: newState.keySchedule.epochAuthenticator }
    }),

    NewMemberAddProposal: wrap(async (req: { group_info: unknown; identity: unknown }) => {
      const groupInfo = decodeGroupInfo(toBytes(req.group_info))
      const cipherSuite = await getCiphersuiteImpl(ciphersuiteNameFromId(groupInfo.groupContext.cipherSuite))
      const { publicPackage, privatePackage } = await generateKeyPackage({
        credential: basicCredential(toBytes(req.identity)),
        cipherSuite,
      })
      const transaction_id = store.insertKeyPackage({ publicPackage, privatePackage, cipherSuite })
      const msg = await proposeAddExternal(groupInfo, publicPackage, privatePackage, cipherSuite)
      return {
        transaction_id,
        proposal: encode(mlsMessageEncoder, msg),
        init_priv: privatePackage.initPrivateKey,
        encryption_priv: privatePackage.hpkePrivateKey,
        signature_priv: privatePackage.signaturePrivateKey,
      }
    }),

    CreateExternalSigner: wrap(async (req: { cipher_suite: number; identity: unknown }) => {
      const csName = ciphersuiteNameFromId(req.cipher_suite)
      const cipherSuite = await getCiphersuiteImpl(csName)
      const identity = toBytes(req.identity)
      const keys = await cipherSuite.signature.keygen()
      const signer_id = store.insertExternalSigner({
        cipherSuite,
        signaturePublicKey: keys.publicKey,
        signaturePrivateKey: keys.signKey,
        identity,
      })
      const sender: ExternalSender = {
        signaturePublicKey: keys.publicKey,
        credential: basicCredential(identity),
      }
      return { signer_id, external_sender: encode(externalSenderEncoder, sender) }
    }),

    AddExternalSigner: wrap(async (req: { state_id: number; external_sender: unknown }) => {
      const entry = store.getGroup(req.state_id)
      const sender = decode(externalSenderDecoder, toBytes(req.external_sender))
      if (!sender) throw new Error("Failed to decode ExternalSender")
      const existingPrev = entry.state.groupContext.extensions.find(
        (e): e is Extract<GroupContextExtension, { extensionType: typeof defaultExtensionTypes.external_senders }> =>
          isDefaultExtension(e) && e.extensionType === defaultExtensionTypes.external_senders,
      )
      const others = entry.state.groupContext.extensions.filter(
        (e) => e.extensionType !== defaultExtensionTypes.external_senders,
      )
      const senders = [...(existingPrev?.extensionData ?? []), sender]
      const newExt: GroupContextExtension = {
        extensionType: defaultExtensionTypes.external_senders,
        extensionData: senders,
      }
      const proposal: ProposalGroupContextExtensions = {
        proposalType: defaultProposalTypes.group_context_extensions,
        groupContextExtensions: { extensions: [...others, newExt] },
      }
      const resp = await makeProposal(store, req.state_id, entry, proposal)
      return { proposal: resp.proposal, signer_index: senders.length - 1 }
    }),

    ExternalSignerProposal: wrap(
      async (req: {
        signer_id: number
        signer_index: number
        group_info: unknown
        ratchet_tree: unknown
        description: {
          proposal_type: unknown
          key_package: unknown
          removed_id: unknown
          psk_id: unknown
          epoch_id: number | string | bigint
          extensions: ProtoExtension[]
          group_id: unknown
          cipher_suite: number
        }
      }) => {
        const signer = store.getExternalSigner(req.signer_id)
        const groupInfo = decodeGroupInfo(toBytes(req.group_info))
        const rtBytes = toBytes(req.ratchet_tree)
        const tree = rtBytes.length > 0 ? decodeRatchetTree(rtBytes) : ratchetTreeFromExtension(groupInfo)
        const typeStr = toStr(req.description.proposal_type)
        const proposal = buildExternalProposal(typeStr, req.description, signer.cipherSuite, groupInfo, tree)
        const msg = await proposeExternal(
          groupInfo,
          proposal,
          signer.signaturePublicKey,
          signer.signaturePrivateKey,
          signer.cipherSuite,
        )
        return { proposal: encode(mlsMessageEncoder, msg) }
      },
    ),
  }
  return handlers
}

// When a pending UpdateProposal from this client is applied by the incoming
// commit, the committer encrypts path secrets to our NEW leaf pubkey, so we
// must decrypt with the new private key. When the commit does NOT apply the
// pending update, secrets are still encrypted to the old key. We don't know
// which case it is until processing, so try the new key first and fall back
// to the original on failure.
async function processCommitWithPendingLeaf(
  entry: GroupEntry,
  commit: ReturnType<typeof decodeFramedMessage>,
  context: MlsContext,
) {
  const pending = entry.pendingLeafUpdate
  if (pending !== undefined) {
    const stateWithNewKey: ClientState = {
      ...entry.state,
      privatePath: updateLeafKey(entry.state.privatePath, pending.hpkePrivateKey),
    }
    try {
      return await processMessage({ context, state: stateWithNewKey, message: commit })
    } catch {
      // commit didn't apply the pending update — fall through to original key
    }
  }
  return await processMessage({ context, state: entry.state, message: commit })
}

function applyPendingLeafUpdate(
  entry: GroupEntry,
  newState: ClientState,
): { state: ClientState; pending: GroupEntry["pendingLeafUpdate"] } {
  const pending = entry.pendingLeafUpdate
  if (pending === undefined) return { state: newState, pending: undefined }
  const ownLeaf = getOwnLeafNode(newState)
  if (ownLeaf === undefined) return { state: newState, pending }
  const sameLen = ownLeaf.hpkePublicKey.length === pending.hpkePublicKey.length
  const matches = sameLen && ownLeaf.hpkePublicKey.every((b, i) => b === pending.hpkePublicKey[i])
  if (!matches) return { state: newState, pending }
  return {
    state: { ...newState, privatePath: updateLeafKey(newState.privatePath, pending.hpkePrivateKey) },
    pending: undefined,
  }
}

async function makeProposal(
  store: Store,
  stateId: number,
  entry: GroupEntry,
  proposal: Proposal,
): Promise<{ proposal: Uint8Array }> {
  const result = await createProposal({
    context: mlsContext(store, entry),
    state: entry.state,
    wireAsPublicMessage: entry.wireAsPublicMessage,
    proposal,
  })
  store.updateGroup(stateId, { state: result.newState })
  return { proposal: encode(mlsMessageEncoder, result.message) }
}

function materializeByValueProposal(raw: unknown, entry: GroupEntry): Proposal | undefined {
  const d = raw as {
    proposal_type?: unknown
    key_package?: unknown
    removed_id?: unknown
    psk_id?: unknown
    epoch_id?: number | string | bigint
    extensions?: ProtoExtension[]
    group_id?: unknown
    cipher_suite?: number
  }
  const typeStr = toStr(d.proposal_type)
  switch (typeStr) {
    case "add": {
      const keyPackage = decodeKeyPackageMessage(toBytes(d.key_package))
      return { proposalType: defaultProposalTypes.add, add: { keyPackage } } satisfies ProposalAdd
    }
    case "remove": {
      const leafIndex = leafIndexForIdentity(entry.state, toBytes(d.removed_id))
      return { proposalType: defaultProposalTypes.remove, remove: { removed: leafIndex } } satisfies ProposalRemove
    }
    case "externalPSK": {
      const pskId = externalPskId(toBytes(d.psk_id), entry.cipherSuite.kdf.size, entry.cipherSuite.rng)
      return { proposalType: defaultProposalTypes.psk, psk: { preSharedKeyId: pskId } } satisfies ProposalPSK
    }
    case "resumptionPSK": {
      const epoch = typeof d.epoch_id === "bigint" ? d.epoch_id : BigInt(d.epoch_id ?? 0)
      const pskId = resumptionPskId(entry.state, epoch, entry.cipherSuite.kdf.size, entry.cipherSuite.rng)
      return { proposalType: defaultProposalTypes.psk, psk: { preSharedKeyId: pskId } } satisfies ProposalPSK
    }
    case "groupContextExtensions": {
      const extensions = (d.extensions ?? []).map(toGroupContextExtension)
      return {
        proposalType: defaultProposalTypes.group_context_extensions,
        groupContextExtensions: { extensions },
      } satisfies ProposalGroupContextExtensions
    }
    case "reinit": {
      const extensions = (d.extensions ?? []).map(toGroupContextExtension)
      return {
        proposalType: defaultProposalTypes.reinit,
        reinit: {
          groupId: toBytes(d.group_id),
          version: protocolVersions.mls10,
          cipherSuite: d.cipher_suite ?? entry.state.groupContext.cipherSuite,
          extensions,
        },
      } satisfies ProposalReinit
    }
    default:
      console.warn(`[by_value] unsupported proposal_type: ${typeStr} (ignored)`)
      return undefined
  }
}

function buildExternalProposal(
  typeStr: string,
  d: {
    key_package: unknown
    removed_id: unknown
    psk_id: unknown
    epoch_id: number | string | bigint
    extensions: ProtoExtension[]
    group_id: unknown
    cipher_suite: number
  },
  cs: { kdf: { size: number }; rng: { randomBytes: (n: number) => Uint8Array } },
  groupInfo: { groupContext: { groupId: Uint8Array; epoch: bigint } },
  tree: RatchetTree | undefined,
): Proposal {
  switch (typeStr) {
    case "add": {
      const keyPackage = decodeKeyPackageMessage(toBytes(d.key_package))
      return { proposalType: defaultProposalTypes.add, add: { keyPackage } }
    }
    case "remove": {
      if (tree === undefined)
        throw new Error("ExternalSignerProposal remove: no ratchet_tree available for identity lookup")
      const leafIndex = leafIndexForIdentityInTree(tree, toBytes(d.removed_id))
      return { proposalType: defaultProposalTypes.remove, remove: { removed: leafIndex } }
    }
    case "externalPSK": {
      const pskId = externalPskId(toBytes(d.psk_id), cs.kdf.size, cs.rng)
      return { proposalType: defaultProposalTypes.psk, psk: { preSharedKeyId: pskId } }
    }
    case "resumptionPSK": {
      const epoch = typeof d.epoch_id === "bigint" ? d.epoch_id : BigInt(d.epoch_id ?? 0)
      const pskId = {
        psktype: 2 as const,
        usage: 1 as const,
        pskGroupId: groupInfo.groupContext.groupId,
        pskEpoch: epoch,
        pskNonce: cs.rng.randomBytes(cs.kdf.size),
      }
      return { proposalType: defaultProposalTypes.psk, psk: { preSharedKeyId: pskId } }
    }
    case "groupContextExtensions": {
      const extensions = (d.extensions ?? []).map(toGroupContextExtension)
      return {
        proposalType: defaultProposalTypes.group_context_extensions,
        groupContextExtensions: { extensions },
      }
    }
    case "reinit": {
      const extensions = (d.extensions ?? []).map(toGroupContextExtension)
      return {
        proposalType: defaultProposalTypes.reinit,
        reinit: {
          groupId: toBytes(d.group_id),
          version: protocolVersions.mls10,
          cipherSuite: d.cipher_suite,
          extensions,
        },
      }
    }
    default:
      throw new Error(`ExternalSignerProposal: unsupported proposal_type "${typeStr}"`)
  }
}

async function finishReInit(
  store: Store,
  stateId: number,
  oldEntry: GroupEntry,
  suspendedState: ClientState,
): Promise<{ reinit_id: number; key_package: Uint8Array; epoch_authenticator: Uint8Array }> {
  if (suspendedState.groupActiveState.kind !== "suspendedPendingReinit")
    throw new Error("Not in suspendedPendingReinit state")
  const newCsName = ciphersuiteNameFromId(suspendedState.groupActiveState.reinit.cipherSuite)
  const newCs = await getCiphersuiteImpl(newCsName)
  const identity = getOwnIdentity(suspendedState) ?? new Uint8Array()
  const newKey = await generateKeyPackage({ credential: basicCredential(identity), cipherSuite: newCs })
  const reinit_id = store.insertReinit({
    suspendedState,
    cipherSuite: oldEntry.cipherSuite,
    wireAsPublicMessage: oldEntry.wireAsPublicMessage,
    newKey: { publicPackage: newKey.publicPackage, privatePackage: newKey.privatePackage },
  })

  store.updateGroup(stateId, { state: suspendedState, pendingNewState: undefined })
  return {
    reinit_id,
    key_package: encode(mlsMessageEncoder, {
      version: protocolVersions.mls10,
      wireformat: wireformats.mls_key_package,
      keyPackage: newKey.publicPackage,
    }),
    epoch_authenticator: suspendedState.keySchedule.epochAuthenticator,
  }
}

function getOwnIdentity(state: ClientState): Uint8Array | undefined {
  try {
    const leaf = getOwnLeafNode(state)
    const cred = leaf.credential
    if (!isDefaultCredential(cred)) return undefined
    if (cred.credentialType !== defaultCredentialTypes.basic) return undefined
    return cred.identity
  } catch {
    return undefined
  }
}

function encodeRatchetTree(state: ClientState): Uint8Array {
  return encode(ratchetTreeEncoder, state.ratchetTree)
}

function decodeRatchetTree(bytes: Uint8Array) {
  const tree = decode(ratchetTreeDecoder, bytes)
  if (!tree) throw new Error("Failed to decode ratchet_tree")
  return tree
}
