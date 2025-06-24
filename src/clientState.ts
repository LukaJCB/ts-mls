import { addToMap } from "./util/addToMap"
import { AuthenticatedContent, AuthenticatedContentCommit, makeProposalRef } from "./authenticatedContent"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Hash } from "./crypto/hash"
import { decryptWithLabel } from "./crypto/hpke"
import { deriveSecret, Kdf } from "./crypto/kdf"
import { Extension, extensionsEqual } from "./extension"
import {
  createConfirmationTag,
  FramedContentAuthDataCommit,
  FramedContentCommit,
  verifyConfirmationTag,
} from "./framedContent"
import { encodeGroupContext, GroupContext } from "./groupContext"
import {
  GroupInfo,
  GroupInfoTBS,
  ratchetTreeFromExtension,
  signGroupInfo,
  verifyGroupInfoConfirmationTag,
  verifyGroupInfoSignature,
} from "./groupInfo"
import { KeyPackage, makeKeyPackageRef, PrivateKeyPackage } from "./keyPackage"
import { deriveKeySchedule, initializeEpoch, initializeKeySchedule, KeySchedule } from "./keySchedule"
import { PreSharedKeyID, updatePskSecret } from "./presharedkey"
import { PrivateMessage } from "./privateMessage"
import { protect, unprotectPrivateMessage } from "./messageProtection"
import { createContentCommitSignature } from "./framedContent"
import { protectApplicationData, protectProposal } from "./messageProtection"
import { protectProposalPublic, protectPublicMessage, unprotectPublicMessage } from "./messageProtectionPublic"

import { PublicMessage } from "./publicMessage"
import {
  addLeafNode,
  encodeRatchetTree,
  findBlankLeafNodeIndex,
  findFirstNonBlankAncestor,
  findLeafIndex,
  getSignaturePublicKeyFromLeafIndex,
  removeLeafNode,
  updateLeafNode,
} from "./ratchetTree"
import { RatchetTree } from "./ratchetTree"
import { createSecretTree, SecretTree } from "./secretTree"
import { getSenderLeafNodeIndex, Sender } from "./sender"
import { createConfirmedHash, createInterimHash } from "./transcriptHash"
import { treeHashRoot } from "./treeHash"
import { leafToNodeIndex, leafWidth, nodeToLeafIndex, root } from "./treemath"
import {
  PathSecret,
  UpdatePath,
  applyUpdatePath,
  createUpdatePath,
  firstCommonAncestor,
  firstMatchAncestor,
} from "./updatePath"
import { base64ToBytes, bytesToBase64 } from "./util/byteArray"
import { constantTimeEqual } from "./util/constantTimeCompare"
import {
  decryptGroupInfo,
  decryptGroupSecrets,
  EncryptedGroupSecrets,
  encryptGroupInfo,
  encryptGroupSecrets,
  Welcome,
} from "./welcome"
import { WireformatName } from "./wireformat"
import { ProposalOrRef } from "./proposalOrRefType"
import { MLSMessage } from "./message"
import { encodeCredential } from "./credential"
import {
  Proposal,
  ProposalAdd,
  ProposalExternalInit,
  ProposalGroupContextExtensions,
  ProposalPSK,
  ProposalReinit,
  ProposalRemove,
  ProposalUpdate,
  Reinit,
} from "./proposal"
import { PathSecrets, pathToPathSecrets } from "./pathSecrets"
import { PrivateKeyPath, mergePrivateKeyPaths, toPrivateKeyPath, updateLeafKey } from "./privateKeyPath"
import { UnappliedProposals, addUnappliedProposal, ProposalWithSender } from "./unappliedProposals"

export type ClientState = {
  groupContext: GroupContext
  keySchedule: KeySchedule
  secretTree: SecretTree
  ratchetTree: RatchetTree
  privatePath: PrivateKeyPath
  signaturePrivateKey: Uint8Array
  unappliedProposals: UnappliedProposals
  confirmationTag: Uint8Array
  historicalResumptionPsks: Map<bigint, Uint8Array>
  suspendedPendingReinit?: Reinit //todo expand this to include removedFromGroup?
}

export async function getCommitSecret(
  tree: RatchetTree,
  nodeIndex: number,
  pathSecret: Uint8Array,
  kdf: Kdf,
): Promise<Uint8Array> {
  const rootIndex = root(leafWidth(tree.length))
  const path = await pathToRoot(tree, nodeIndex, pathSecret, kdf)
  const rootSecret = path[rootIndex]

  if (rootSecret === undefined) throw new Error("Could not find secret for root")
  return deriveSecret(rootSecret, "path", kdf)
}

export async function pathToRoot(
  tree: RatchetTree,
  nodeIndex: number,
  pathSecret: Uint8Array,
  kdf: Kdf,
): Promise<PathSecrets> {
  const rootIndex = root(leafWidth(tree.length))
  let currentIndex = nodeIndex
  let pathSecrets = { [nodeIndex]: pathSecret }
  while (currentIndex != rootIndex) {
    const nextIndex = findFirstNonBlankAncestor(tree, currentIndex)
    const nextSecret = await deriveSecret(pathSecrets[currentIndex]!, "path", kdf)

    pathSecrets[nextIndex] = nextSecret
    currentIndex = nextIndex
  }

  return pathSecrets
}

export type ProcessPrivateMessageResult =
  | {
      kind: "newState"
      newState: ClientState
    }
  | { kind: "applicationMessage"; message: Uint8Array; newState: ClientState }

/**
 * Process private message and apply proposal or commit and return the updated ClientState or return an application message
 */
export async function processPrivateMessage(
  state: ClientState,
  pm: PrivateMessage,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
): Promise<ProcessPrivateMessageResult> {
  const result = await unprotectPrivateMessage(
    state.keySchedule.senderDataSecret,
    pm,
    state.secretTree,
    state.ratchetTree,
    state.groupContext,
    cs,
  )

  const newState = { ...state, secretTree: result.tree }

  if (result.content.content.contentType === "application") {
    return { kind: "applicationMessage", message: result.content.content.applicationData, newState }
  } else if (result.content.content.contentType === "commit") {
    return {
      kind: "newState",
      newState: await processCommit(
        newState,
        result.content as AuthenticatedContentCommit,
        "mls_private_message",
        pskSearch,
        cs,
      ), //todo solve with types
    }
  } else {
    return {
      kind: "newState",
      newState: await processProposal(newState, result.content, result.content.content.proposal, cs.hash),
    }
  }
}

export async function processPublicMessage(
  state: ClientState,
  pm: PublicMessage,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
): Promise<ClientState> {
  const content = await unprotectPublicMessage(
    state.keySchedule.membershipKey,
    state.groupContext,
    state.ratchetTree,
    pm,
    cs,
  )

  if (content === undefined) throw new Error("Could not unprotect private message")

  if (content.content.contentType === "proposal")
    return processProposal(state, content, content.content.proposal, cs.hash)
  else {
    return processCommit(state, content as AuthenticatedContentCommit, "mls_public_message", pskSearch, cs) //todo solve with types
  }
}

async function processCommit(
  state: ClientState,
  content: AuthenticatedContentCommit,
  wireformat: WireformatName,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
): Promise<ClientState> {
  if (content.content.epoch !== state.groupContext.epoch) throw new Error("Could not validate epoch")

  const senderLeafIndex = content.content.sender.senderType === "member" ? content.content.sender.leafIndex : undefined

  //TODO Verify that the proposals vector is valid according to the rules in Section 12.2.
  //TODO Verify that all PreSharedKey proposals in the proposals vector are available.

  const result = await applyProposals(state, content.content.commit.proposals, senderLeafIndex, pskSearch, cs)

  if (result.needsUpdatePath && content.content.commit.path === undefined) throw new Error("Update path is required")

  const groupContextWithExtensions =
    result.additionalResult.kind === "memberCommit" && result.additionalResult.extensions.length > 0
      ? { ...state.groupContext, extensions: result.additionalResult.extensions }
      : state.groupContext

  const [pkp, commitSecret, tree] = await applyTreeUpdate(
    content.content.commit.path,
    content.content.sender,
    result.tree,
    cs,
    state,
    groupContextWithExtensions,
    result.additionalResult.kind === "memberCommit"
      ? result.additionalResult.addedLeafNodes.map((l) => leafToNodeIndex(l[0]))
      : [findBlankLeafNodeIndex(result.tree) ?? result.tree.length + 1],
    cs.kdf,
  )

  const newTreeHash = await treeHashRoot(tree, cs.hash)

  if (content.auth.contentType !== "commit") throw new Error("Received content as commit, but not auth") //todo solve this with types?
  const updatedGroupContext = await nextEpochContext(
    groupContextWithExtensions,
    wireformat,
    content.content,
    content.auth.signature,
    newTreeHash,
    state.confirmationTag,
    cs.hash,
  )

  const initSecret =
    result.additionalResult.kind === "externalCommit"
      ? result.additionalResult.externalInitSecret
      : state.keySchedule.initSecret

  const epochSecrets = await initializeEpoch(initSecret, commitSecret, updatedGroupContext, result.pskSecret, cs.kdf)

  const confirmationTagValid = await verifyConfirmationTag(
    epochSecrets.keySchedule.confirmationKey,
    content.auth.confirmationTag,
    updatedGroupContext.confirmedTranscriptHash,
    cs.hash,
  )

  if (!confirmationTagValid) throw new Error("Could not verify confirmation tag")

  const secretTree = await createSecretTree(leafWidth(tree.length), epochSecrets.keySchedule.encryptionSecret, cs.kdf)

  return {
    ...state,
    secretTree,
    ratchetTree: tree,
    privatePath: pkp,
    groupContext: updatedGroupContext,
    keySchedule: epochSecrets.keySchedule,
    confirmationTag: content.auth.confirmationTag,
    historicalResumptionPsks: addToMap(
      state.historicalResumptionPsks,
      state.groupContext.epoch,
      state.keySchedule.resumptionPsk,
    ),
    unappliedProposals: {},
    suspendedPendingReinit: result.additionalResult.kind === "reinit" ? result.additionalResult.reinit : undefined,
  }
}

function filterNewLeaves(resolution: number[], excludeNodes: number[]): number[] {
  const set = new Set(excludeNodes)
  return resolution.filter((i) => !set.has(i))
}

async function applyTreeUpdate(
  path: UpdatePath | undefined,
  sender: Sender,
  tree: RatchetTree,
  cs: CiphersuiteImpl,
  state: ClientState,
  groupContext: GroupContext,
  excludeNodes: number[],
  kdf: Kdf,
): Promise<[PrivateKeyPath, Uint8Array, RatchetTree]> {
  if (path === undefined) return [state.privatePath, new Uint8Array(kdf.size), tree] as const
  if (sender.senderType === "member") {
    const updatedTree = await applyUpdatePath(tree, sender.leafIndex, path, cs.hash)

    const [pkp, commitSecret] = await updatePrivateKeyPath(
      updatedTree,
      state,
      sender.leafIndex,
      { ...groupContext, treeHash: await treeHashRoot(updatedTree, cs.hash), epoch: groupContext.epoch + 1n },
      path,
      excludeNodes,
      cs,
    )
    return [pkp, commitSecret, updatedTree] as const
  } else {
    const [treeWithLeafNode, leafNodeIndex] = addLeafNode(tree, path.leafNode)

    const senderLeafIndex = nodeToLeafIndex(leafNodeIndex)
    const updatedTree = await applyUpdatePath(treeWithLeafNode, senderLeafIndex, path, cs.hash)

    const [pkp, commitSecret] = await updatePrivateKeyPath(
      updatedTree,
      state,
      senderLeafIndex,
      { ...groupContext, treeHash: await treeHashRoot(updatedTree, cs.hash), epoch: groupContext.epoch + 1n },
      path,
      excludeNodes,
      cs,
    )
    return [pkp, commitSecret, updatedTree] as const
  }
}

async function updatePrivateKeyPath(
  tree: RatchetTree,
  state: ClientState,
  leafNodeIndex: number,
  groupContext: GroupContext,
  path: UpdatePath,
  excludeNodes: number[],
  cs: CiphersuiteImpl,
): Promise<[PrivateKeyPath, Uint8Array]> {
  const secret = await applyUpdatePathSecret(
    tree,
    state.privatePath,
    leafNodeIndex,
    groupContext,
    path,
    excludeNodes,
    cs,
  )
  const pathSecrets = await pathToRoot(tree, secret.nodeIndex, secret.pathSecret, cs.kdf)
  const newPkp = mergePrivateKeyPaths(
    state.privatePath,
    await toPrivateKeyPath(pathSecrets, state.privatePath.leafIndex, cs),
  )

  const rootIndex = root(leafWidth(tree.length))
  const rootSecret = pathSecrets[rootIndex]
  if (rootSecret === undefined) throw new Error("Could not find secret for root")

  const commitSecret = await deriveSecret(rootSecret, "path", cs.kdf)
  return [newPkp, commitSecret] as const
}

export async function processProposal(
  state: ClientState,
  content: AuthenticatedContent,
  proposal: Proposal,
  h: Hash,
): Promise<ClientState> {
  const ref = await makeProposalRef(content, h)
  return {
    ...state,
    unappliedProposals: addUnappliedProposal(
      ref,
      state.unappliedProposals,
      proposal,
      getSenderLeafNodeIndex(content.content.sender),
    ),
  }
}

export type Proposals = {
  add: { senderLeafIndex: number | undefined; proposal: ProposalAdd }[]
  update: { senderLeafIndex: number | undefined; proposal: ProposalUpdate }[]
  remove: { senderLeafIndex: number | undefined; proposal: ProposalRemove }[]
  psk: { senderLeafIndex: number | undefined; proposal: ProposalPSK }[]
  reinit: { senderLeafIndex: number | undefined; proposal: ProposalReinit }[]
  external_init: { senderLeafIndex: number | undefined; proposal: ProposalExternalInit }[]
  group_context_extensions: { senderLeafIndex: number | undefined; proposal: ProposalGroupContextExtensions }[]
}

const emptyProposals: Proposals = {
  add: [],
  update: [],
  remove: [],
  psk: [],
  reinit: [],
  external_init: [],
  group_context_extensions: [],
}

type ApplyProposalsResult = {
  tree: RatchetTree
  pskSecret: Uint8Array<ArrayBufferLike>
  pskIds: PreSharedKeyID[]
  needsUpdatePath: boolean
  additionalResult: ApplyProposalsData
}

type ApplyProposalsData =
  | { kind: "memberCommit"; addedLeafNodes: [number, KeyPackage][]; extensions: Extension[] }
  | { kind: "externalCommit"; externalInitSecret: Uint8Array }
  | { kind: "reinit"; reinit: Reinit }

function flattenExtensions(groupContextExtensions: { proposal: ProposalGroupContextExtensions }[]): Extension[] {
  return groupContextExtensions.reduce((acc, { proposal }) => {
    return [...acc, ...proposal.groupContextExtensions.extensions]
  }, [] as Extension[])
}

/**
 * Helper to accumulate PSK secret and IDs from grouped PSK proposals.
 */
async function accumulatePskSecret(
  groupedPsk: { proposal: ProposalPSK }[],
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
  zeroes: Uint8Array,
): Promise<[Uint8Array, PreSharedKeyID[]]> {
  return groupedPsk.reduce<Promise<[Uint8Array, PreSharedKeyID[]]>>(
    async (acc, cur, index) => {
      const [previousSecret, ids] = await acc
      const psk = pskSearch.findPsk(cur.proposal.psk.preSharedKeyId)
      if (psk === undefined) throw new Error("Could not find pskId referenced in proposal")
      const pskSecret = await updatePskSecret(
        previousSecret,
        cur.proposal.psk.preSharedKeyId,
        psk,
        index,
        groupedPsk.length,
        cs,
      )
      return [pskSecret, [...ids, cur.proposal.psk.preSharedKeyId]]
    },
    Promise.resolve([zeroes, []]),
  )
}

async function applyProposals(
  state: ClientState,
  proposals: ProposalOrRef[],
  senderLeafIndex: number | undefined,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
): Promise<ApplyProposalsResult> {
  const allProposals = proposals.reduce((acc, cur) => {
    if (cur.proposalOrRefType === "proposal") return [...acc, { proposal: cur.proposal, senderLeafIndex }]

    const p = state.unappliedProposals[bytesToBase64(cur.reference)]
    if (p === undefined) throw new Error("Could not find proposal with supplied reference")
    return [...acc, p]
  }, [] as ProposalWithSender[])

  const grouped = allProposals.reduce((acc, cur) => {
    const proposal = acc[cur.proposal.proposalType] ?? []
    return { ...acc, [cur.proposal.proposalType]: [...proposal, cur] }
  }, emptyProposals)

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const isExternalInit = grouped.external_init.length > 0

  if (!isExternalInit) {
    if (grouped.reinit.length > 0) {
      if (allProposals.length !== 1) throw new Error("Reinit proposal needs to be commited by itself")

      const reinit = grouped.reinit.at(0)!.proposal.reinit

      return {
        tree: state.ratchetTree,
        pskSecret: zeroes,
        pskIds: [],
        needsUpdatePath: false,
        additionalResult: {
          kind: "reinit",
          reinit,
        },
      }
    }

    const newExtensions = flattenExtensions(grouped.group_context_extensions)

    const [mutatedTree, addedLeafNodes] = applyTreeMutations(state.ratchetTree, grouped)

    const [updatedPskSecret, pskIds] = await accumulatePskSecret(grouped.psk, pskSearch, cs, zeroes)

    const needsUpdatePath =
      allProposals.length === 0 || Object.values(grouped.update).length > 1 || Object.values(grouped.remove).length > 1

    return {
      tree: mutatedTree,
      pskSecret: updatedPskSecret,
      additionalResult: {
        kind: "memberCommit" as const,
        addedLeafNodes,
        extensions: newExtensions,
      },
      pskIds,
      needsUpdatePath,
    }
  } else {
    if (grouped.external_init.length > 1) throw new Error("Cannot contain more than one external_init proposal")

    if (grouped.remove.length > 1) throw new Error("Cannot contain more than one remove proposal")

    if (
      grouped.add.length > 0 ||
      grouped.group_context_extensions.length > 0 ||
      grouped.reinit.length > 0 ||
      grouped.update.length > 0
    )
      throw new Error("Invalid proposals")

    const treeAfterRemove = grouped.remove.reduce((acc, { proposal }) => {
      return removeLeafNode(acc, proposal.remove.removed)
    }, state.ratchetTree)

    const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

    const [updatedPskSecret, pskIds] = await accumulatePskSecret(grouped.psk, pskSearch, cs, zeroes)

    const initProposal = grouped.external_init.at(0)!

    const externalKeyPair = await cs.hpke.deriveKeyPair(state.keySchedule.externalSecret)

    const externalInitSecret = await importSecret(
      await cs.hpke.exportPrivateKey(externalKeyPair.privateKey),
      initProposal.proposal.externalInit.kemOutput,
      cs,
    )

    return {
      needsUpdatePath: true,
      tree: treeAfterRemove,
      pskSecret: updatedPskSecret,
      pskIds,
      additionalResult: { kind: "externalCommit", externalInitSecret },
    }
  }
}

export type CreateCommitResult = { newState: ClientState; welcome: Welcome | undefined; commit: MLSMessage }

export async function createCommit(
  state: ClientState,
  pskSearch: PskIndex,
  publicMessage: boolean,
  extraProposals: Proposal[],
  cs: CiphersuiteImpl,
  ratchetTreeExtension: boolean = false,
): Promise<CreateCommitResult> {
  if (state.suspendedPendingReinit !== undefined) throw new Error("Group is suspended pending reinit")

  const refs: ProposalOrRef[] = Object.keys(state.unappliedProposals).map((p) => ({
    proposalOrRefType: "reference",
    reference: base64ToBytes(p),
  }))

  const wireformat = publicMessage ? "mls_public_message" : "mls_private_message"

  const proposals: ProposalOrRef[] = extraProposals.map((p) => ({ proposalOrRefType: "proposal", proposal: p }))

  const allProposals = [...refs, ...proposals]

  const res = await applyProposals(state, allProposals, state.privatePath.leafIndex, pskSearch, cs)

  if (res.additionalResult.kind === "externalCommit") throw new Error("Cannot create externalCommit as a member")

  const suspendedPendingReinit = res.additionalResult.kind === "reinit" ? res.additionalResult.reinit : undefined

  const [tree, updatePath, pathSecrets, newPrivateKey] = res.needsUpdatePath
    ? await createUpdatePath(res.tree, state.privatePath.leafIndex, state.groupContext, state.signaturePrivateKey, cs)
    : [res.tree, undefined, [] as PathSecret[], undefined]

  const updatedExtensions =
    res.additionalResult.kind === "memberCommit" && res.additionalResult.extensions.length > 0
      ? res.additionalResult.extensions
      : state.groupContext.extensions

  const groupContextWithExtensions = { ...state.groupContext, extensions: updatedExtensions }

  const privateKeys = mergePrivateKeyPaths(
    newPrivateKey !== undefined
      ? updateLeafKey(state.privatePath, await cs.hpke.exportPrivateKey(newPrivateKey))
      : state.privatePath,
    await toPrivateKeyPath(pathToPathSecrets(pathSecrets), state.privatePath.leafIndex, cs),
  )

  const lastPathSecret = pathSecrets.at(-1)

  const commitSecret =
    lastPathSecret === undefined
      ? new Uint8Array(cs.kdf.size)
      : await deriveSecret(lastPathSecret.secret, "path", cs.kdf)

  const authenticatedData = new Uint8Array()

  const { signature, framedContent } = await createContentCommitSignature(
    state.groupContext,
    wireformat,
    { proposals: allProposals, path: updatePath },
    { senderType: "member", leafIndex: state.privatePath.leafIndex },
    authenticatedData,
    state.signaturePrivateKey,
    cs.signature,
  )

  const treeHash = await treeHashRoot(tree, cs.hash)

  const updatedGroupContext = await nextEpochContext(
    groupContextWithExtensions,
    wireformat,
    framedContent,
    signature,
    treeHash,
    state.confirmationTag,
    cs.hash,
  )

  const epochSecrets = await initializeEpoch(
    state.keySchedule.initSecret,
    commitSecret,
    updatedGroupContext,
    res.pskSecret,
    cs.kdf,
  )

  const confirmationTag = await createConfirmationTag(
    epochSecrets.keySchedule.confirmationKey,
    updatedGroupContext.confirmedTranscriptHash,
    cs.hash,
  )

  const authData: FramedContentAuthDataCommit = {
    contentType: framedContent.contentType,
    signature,
    confirmationTag,
  }

  const [commit] = await protectCommit(publicMessage, state, authenticatedData, framedContent, authData, cs)

  const groupInfo = ratchetTreeExtension
    ? await createGroupInfoWithRatchetTree(updatedGroupContext, confirmationTag, state, tree, cs)
    : await createGroupInfo(updatedGroupContext, confirmationTag, state, cs)

  const encryptedGroupInfo = await encryptGroupInfo(groupInfo, epochSecrets.welcomeSecret, cs)

  const encryptedGroupSecrets: EncryptedGroupSecrets[] =
    res.additionalResult.kind === "memberCommit"
      ? await Promise.all(
          res.additionalResult.addedLeafNodes.map(async ([leafNodeIndex, keyPackage]) => {
            const nodeIndex = firstCommonAncestor(tree, leafNodeIndex, state.privatePath.leafIndex)
            const pathSecret = pathSecrets.find((ps) => ps.nodeIndex === nodeIndex)
            const pk = await cs.hpke.importPublicKey(keyPackage.initKey)
            const egs = await encryptGroupSecrets(
              pk,
              encryptedGroupInfo,
              { joinerSecret: epochSecrets.joinerSecret, pathSecret: pathSecret?.secret, psks: res.pskIds },
              cs.hpke,
            )

            const ref = await makeKeyPackageRef(keyPackage, cs.hash)

            return { newMember: ref, encryptedGroupSecrets: { kemOutput: egs.enc, ciphertext: egs.ct } }
          }),
        )
      : []

  const welcome: Welcome | undefined =
    encryptedGroupSecrets.length > 0
      ? {
          cipherSuite: updatedGroupContext.cipherSuite,
          secrets: encryptedGroupSecrets,
          encryptedGroupInfo,
        }
      : undefined

  const newState: ClientState = {
    groupContext: updatedGroupContext,
    ratchetTree: tree,
    secretTree: await createSecretTree(leafWidth(tree.length), epochSecrets.keySchedule.encryptionSecret, cs.kdf),
    keySchedule: epochSecrets.keySchedule,
    privatePath: privateKeys,
    unappliedProposals: {},
    historicalResumptionPsks: addToMap(
      state.historicalResumptionPsks,
      state.groupContext.epoch,
      state.keySchedule.resumptionPsk,
    ),
    confirmationTag,
    signaturePrivateKey: state.signaturePrivateKey,
    suspendedPendingReinit,
  }

  return { newState, welcome, commit }
}

export async function createGroupInfo(
  groupContext: GroupContext,
  confirmationTag: Uint8Array,
  state: ClientState,
  cs: CiphersuiteImpl,
): Promise<GroupInfo> {
  const groupInfoTbs: GroupInfoTBS = {
    groupContext: groupContext,
    extensions: groupContext.extensions,
    confirmationTag,
    signer: state.privatePath.leafIndex,
  }

  return signGroupInfo(groupInfoTbs, state.signaturePrivateKey, cs.signature)
}

export async function createGroupInfoWithRatchetTree(
  groupContext: GroupContext,
  confirmationTag: Uint8Array,
  state: ClientState,
  tree: RatchetTree,
  cs: CiphersuiteImpl,
): Promise<GroupInfo> {
  const gi = await createGroupInfo(groupContext, confirmationTag, state, cs)

  const encodedTree = encodeRatchetTree(tree)

  return { ...gi, extensions: [...gi.extensions, { extensionType: "ratchet_tree", extensionData: encodedTree }] }
}

export async function createGroupInfoWithExternalPub(state: ClientState, cs: CiphersuiteImpl): Promise<GroupInfo> {
  const gi = await createGroupInfo(state.groupContext, state.confirmationTag, state, cs)

  const externalKeyPair = await cs.hpke.deriveKeyPair(state.keySchedule.externalSecret)
  const externalPub = await cs.hpke.exportPublicKey(externalKeyPair.publicKey)

  return { ...gi, extensions: [...gi.extensions, { extensionType: "external_pub", extensionData: externalPub }] }
}

async function protectCommit(
  publicMessage: boolean,
  state: ClientState,
  authenticatedData: Uint8Array,
  content: FramedContentCommit,
  authData: FramedContentAuthDataCommit,
  cs: CiphersuiteImpl,
): Promise<[MLSMessage, SecretTree]> {
  const wireformat = publicMessage ? "mls_public_message" : "mls_private_message"

  const authenticatedContent: AuthenticatedContentCommit = {
    wireformat,
    content,
    auth: authData,
  }

  if (publicMessage) {
    const msg = await protectPublicMessage(
      state.keySchedule.membershipKey,
      state.groupContext,
      authenticatedContent,
      cs,
    )

    return [{ version: "mls10", wireformat: "mls_public_message", publicMessage: msg }, state.secretTree]
  } else {
    const res = await protect(
      state.keySchedule.senderDataSecret,
      authenticatedData,
      state.groupContext,
      state.secretTree,
      { ...content, auth: authData },
      state.privatePath.leafIndex,
      cs,
    )

    return [{ version: "mls10", wireformat: "mls_private_message", privateMessage: res.privateMessage }, res.tree]
  }
}

export async function applyUpdatePathSecret(
  tree: RatchetTree,
  privatePath: PrivateKeyPath,
  senderLeafIndex: number,
  gc: GroupContext,
  path: UpdatePath,
  excludeNodes: number[],
  cs: CiphersuiteImpl,
): Promise<{ nodeIndex: number; pathSecret: Uint8Array }> {
  const {
    nodeIndex: ancestorNodeIndex,
    resolution,
    updateNode,
  } = firstMatchAncestor(tree, privatePath.leafIndex, senderLeafIndex, path)

  for (const [i, nodeIndex] of filterNewLeaves(resolution, excludeNodes).entries()) {
    if (privatePath.privateKeys[nodeIndex] !== undefined) {
      const key = await cs.hpke.importPrivateKey(privatePath.privateKeys[nodeIndex]!)
      const ct = updateNode?.encryptedPathSecret[i]!

      const pathSecret = await decryptWithLabel(
        key,
        "UpdatePathNode",
        encodeGroupContext(gc),
        ct.kemOutput,
        ct.ciphertext,
        cs.hpke,
      )
      return { nodeIndex: ancestorNodeIndex, pathSecret }
    }
  }

  throw new Error("No overlap between provided private keys and update path")
}

export interface PskIndex {
  findPsk(preSharedKeyId: PreSharedKeyID): Uint8Array | undefined
}

export function makePskIndex(state: ClientState | undefined, externalPsks: Record<string, Uint8Array>): PskIndex {
  return {
    findPsk(preSharedKeyId) {
      if (preSharedKeyId.psktype === "external") {
        return externalPsks[bytesToBase64(preSharedKeyId.pskId)]
      }

      if (state !== undefined && constantTimeEqual(preSharedKeyId.pskGroupId, state.groupContext.groupId)) {
        if (preSharedKeyId.pskEpoch === state.groupContext.epoch) return state.keySchedule.resumptionPsk
        else return state.historicalResumptionPsks.get(preSharedKeyId.pskEpoch)
      }
    },
  }
}

export const emptyPskIndex: PskIndex = {
  findPsk(_preSharedKeyId) {
    return undefined
  },
}

export async function nextEpochContext(
  groupContext: GroupContext,
  wireformat: WireformatName,
  content: FramedContentCommit,
  signature: Uint8Array,
  updatedTreeHash: Uint8Array,
  confirmationTag: Uint8Array,
  h: Hash,
): Promise<GroupContext> {
  const interimTranscriptHash = await createInterimHash(groupContext.confirmedTranscriptHash, confirmationTag, h)
  const newConfirmedHash = await createConfirmedHash(interimTranscriptHash, { wireformat, content, signature }, h)

  return {
    ...groupContext,
    epoch: groupContext.epoch + 1n,
    treeHash: updatedTreeHash,
    confirmedTranscriptHash: newConfirmedHash,
  }
}

export async function joinGroupExternal(
  groupInfo: GroupInfo,
  keyPackage: KeyPackage,
  privateKeys: PrivateKeyPackage,
  tree: RatchetTree | undefined,
  resync: boolean,
  cs: CiphersuiteImpl,
) {
  const externalPub = groupInfo.extensions.find((ex) => ex.extensionType === "external_pub")

  if (externalPub === undefined) throw new Error("Could not find external_pub extension")

  const { enc, secret: initSecret } = await exportSecret(externalPub.extensionData, cs)

  const ratchetTree = ratchetTreeFromExtension(groupInfo) ?? tree

  if (ratchetTree === undefined) throw new Error("No RatchetTree passed and no ratchet_tree extension")

  const signaturePublicKey = getSignaturePublicKeyFromLeafIndex(ratchetTree, groupInfo.signer)

  const groupInfoSignatureVerified = verifyGroupInfoSignature(groupInfo, signaturePublicKey, cs.signature)

  if (!groupInfoSignatureVerified) throw new Error("Could not verify groupInfo Signature")

  const formerLeafIndex = resync
    ? nodeToLeafIndex(
        ratchetTree.findIndex((n) => {
          if (n !== undefined && n.nodeType === "leaf") {
            return constantTimeEqual(
              encodeCredential(n.leaf.credential),
              encodeCredential(keyPackage.leafNode.credential),
            )
          }
          return false
        }),
      )
    : undefined

  const updatedTree = formerLeafIndex !== undefined ? removeLeafNode(ratchetTree, formerLeafIndex) : ratchetTree

  const [treeWithNewLeafNode, newLeafNodeIndex] = addLeafNode(updatedTree, keyPackage.leafNode)

  const [newTree, updatePath, pathSecrets, newPrivateKey] = await createUpdatePath(
    treeWithNewLeafNode,
    nodeToLeafIndex(newLeafNodeIndex),
    groupInfo.groupContext,
    privateKeys.signaturePrivateKey,
    cs,
  )

  const privateKeyPath = updateLeafKey(
    await toPrivateKeyPath(pathToPathSecrets(pathSecrets), nodeToLeafIndex(newLeafNodeIndex), cs),
    await cs.hpke.exportPrivateKey(newPrivateKey),
  )

  const lastPathSecret = pathSecrets.at(-1)

  const commitSecret =
    lastPathSecret === undefined
      ? new Uint8Array(cs.kdf.size) //todo is this right?
      : await deriveSecret(lastPathSecret.secret, "path", cs.kdf)

  const externalInitProposal: ProposalExternalInit = {
    proposalType: "external_init",
    externalInit: { kemOutput: enc },
  }
  const proposals: Proposal[] =
    formerLeafIndex !== undefined
      ? [{ proposalType: "remove", remove: { removed: formerLeafIndex } }, externalInitProposal]
      : [externalInitProposal]

  const pskSecret = new Uint8Array(cs.kdf.size)

  const { signature, framedContent } = await createContentCommitSignature(
    groupInfo.groupContext,
    "mls_public_message",
    { proposals: proposals.map((p) => ({ proposalOrRefType: "proposal", proposal: p })), path: updatePath },
    {
      senderType: "new_member_commit",
    },
    new Uint8Array(),
    privateKeys.signaturePrivateKey,
    cs.signature,
  )

  const treeHash = await treeHashRoot(newTree, cs.hash)

  const groupContext = await nextEpochContext(
    groupInfo.groupContext,
    "mls_public_message",
    framedContent,
    signature,
    treeHash,
    groupInfo.confirmationTag,
    cs.hash,
  )

  const epochSecrets = await initializeEpoch(initSecret, commitSecret, groupContext, pskSecret, cs.kdf)

  const confirmationTag = await createConfirmationTag(
    epochSecrets.keySchedule.confirmationKey,
    groupContext.confirmedTranscriptHash,
    cs.hash,
  )

  const state: ClientState = {
    ratchetTree: newTree,
    groupContext: groupContext,
    secretTree: await createSecretTree(leafWidth(newTree.length), epochSecrets.keySchedule.encryptionSecret, cs.kdf),
    privatePath: privateKeyPath,
    confirmationTag,
    historicalResumptionPsks: new Map(),
    signaturePrivateKey: privateKeys.signaturePrivateKey,
    keySchedule: epochSecrets.keySchedule,
    unappliedProposals: {},
  }

  const authenticatedContent: AuthenticatedContentCommit = {
    content: framedContent,
    auth: { signature, confirmationTag, contentType: "commit" },
    wireformat: "mls_public_message",
  }

  const msg = await protectPublicMessage(epochSecrets.keySchedule.membershipKey, groupContext, authenticatedContent, cs)

  return { publicMessage: msg, newState: state }
}

export async function joinGroup(
  welcome: Welcome,
  keyPackage: KeyPackage,
  privateKeys: PrivateKeyPackage,
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
  ratchetTree?: RatchetTree,
  resumingFromState?: ClientState,
): Promise<ClientState> {
  const keyPackageRef = await makeKeyPackageRef(keyPackage, cs.hash)
  const privKey = await cs.hpke.importPrivateKey(privateKeys.initPrivateKey)
  const groupSecrets = await decryptGroupSecrets(privKey, keyPackageRef, welcome, cs.hpke)

  if (groupSecrets === undefined) throw new Error("Could not decrypt group secrets")

  const includesResumption = groupSecrets.psks.reduce((acc, cur) => {
    if (cur.psktype === "resumption" && (cur.usage === "branch" || cur.usage === "reinit")) {
      if (acc) throw new Error("Encountered multiple resumption PSKs")
      return true
    }
    return false
  }, false)

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const [pskSecret, pskIds] = await groupSecrets.psks.reduce(
    async (acc, cur, index) => {
      const [previousSecret, ids] = await acc
      const psk = pskSearch.findPsk(cur)

      if (psk === undefined) throw new Error("Could not find pskId referenced in proposal")

      const pskSecret = await updatePskSecret(previousSecret, cur, psk, index, groupSecrets.psks.length, cs)
      return [pskSecret, [...ids, cur]]
    },
    Promise.resolve([zeroes, [] as PreSharedKeyID[]] as const),
  )

  const gi = await decryptGroupInfo(welcome, groupSecrets.joinerSecret, pskSecret, cs)
  if (gi === undefined) throw new Error("Could not decrypt group info")

  const resumptionPsk = pskIds.find((id) => id.psktype === "resumption")
  if (resumptionPsk !== undefined) {
    if (resumingFromState === undefined) throw new Error("No prior state passed for resumption")

    if (resumptionPsk.pskEpoch !== resumingFromState.groupContext.epoch) throw new Error("Epoch mismatch")

    if (!constantTimeEqual(resumptionPsk.pskGroupId, resumingFromState.groupContext.groupId))
      throw new Error("old groupId mismatch")
    if (gi.groupContext.epoch !== 1n) throw new Error("Resumption must be started at epoch 1")

    if (resumptionPsk.usage === "reinit") {
      if (resumingFromState.suspendedPendingReinit === undefined)
        throw new Error("Found reinit psk but no old suspended clientState")

      if (!constantTimeEqual(resumingFromState.suspendedPendingReinit.groupId, gi.groupContext.groupId))
        throw new Error("new groupId mismatch")

      if (resumingFromState.suspendedPendingReinit.version !== gi.groupContext.version)
        throw new Error("Version mismatch")

      if (resumingFromState.suspendedPendingReinit.cipherSuite !== gi.groupContext.cipherSuite)
        throw new Error("Ciphersuite mismatch")

      if (!extensionsEqual(resumingFromState.suspendedPendingReinit.extensions, gi.groupContext.extensions))
        throw new Error("Extensions mismatch")
    }
  }

  const tree = ratchetTreeFromExtension(gi) ?? ratchetTree

  if (tree === undefined) throw new Error("No RatchetTree passed and no ratchet_tree extension")

  const signerNode = tree[leafToNodeIndex(gi.signer)]

  if (signerNode === undefined) {
    throw new Error("Undefined")
  }
  if (signerNode.nodeType === "parent") throw new Error("Expected non blank leaf node")

  const groupInfoSignatureVerified = verifyGroupInfoSignature(gi, signerNode.leaf.signaturePublicKey, cs.signature)

  if (!groupInfoSignatureVerified) throw new Error("Could not verify groupInfo signature")

  //todo more validation

  const newLeaf = findLeafIndex(tree, keyPackage.leafNode)

  if (newLeaf === undefined) throw new Error("Could not find own leaf when processing welcome")

  const privateKeyPath: PrivateKeyPath = {
    leafIndex: newLeaf,
    privateKeys: { [leafToNodeIndex(newLeaf)]: privateKeys.hpkePrivateKey },
  }

  const ancestorNodeIndex = firstCommonAncestor(tree, newLeaf, gi.signer)

  const updatedPkp =
    groupSecrets.pathSecret === undefined
      ? privateKeyPath
      : mergePrivateKeyPaths(
          await toPrivateKeyPath(
            await pathToRoot(tree, ancestorNodeIndex, groupSecrets.pathSecret, cs.kdf),
            newLeaf,
            cs,
          ),
          privateKeyPath,
        )

  const keySchedule = await deriveKeySchedule(groupSecrets.joinerSecret, pskSecret, gi.groupContext, cs.kdf)

  const confirmationTagVerified = await verifyGroupInfoConfirmationTag(gi, groupSecrets.joinerSecret, pskSecret, cs)

  if (!confirmationTagVerified) throw new Error("Could not verify confirmation tag")

  const secretTree = await createSecretTree(leafWidth(tree.length), keySchedule.encryptionSecret, cs.kdf)

  const newGroupContext = { ...gi.groupContext }

  if (includesResumption) {
    //todo validate resumption
  }

  return {
    groupContext: newGroupContext,
    ratchetTree: tree,
    privatePath: updatedPkp,
    signaturePrivateKey: privateKeys.signaturePrivateKey,
    confirmationTag: gi.confirmationTag,
    unappliedProposals: {},
    keySchedule,
    secretTree,
    historicalResumptionPsks: new Map(),
  }
}

export async function createGroup(
  groupId: Uint8Array,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  extensions: Extension[],
  cs: CiphersuiteImpl,
): Promise<ClientState> {
  const ratchetTree: RatchetTree = [{ nodeType: "leaf", leaf: keyPackage.leafNode }]

  const privatePath: PrivateKeyPath = {
    leafIndex: 0,
    privateKeys: { [0]: privateKeyPackage.hpkePrivateKey },
  }

  const confirmedTranscriptHash = new Uint8Array()

  const groupContext: GroupContext = {
    version: "mls10",
    cipherSuite: cs.name,
    epoch: 0n,
    treeHash: await treeHashRoot(ratchetTree, cs.hash),
    groupId,
    extensions,
    confirmedTranscriptHash,
  }

  const epochSecret = cs.rng.randomBytes(cs.kdf.size)

  const keySchedule = await initializeKeySchedule(epochSecret, cs.kdf)

  const confirmationTag = await createConfirmationTag(keySchedule.confirmationKey, confirmedTranscriptHash, cs.hash)

  const secretTree = await createSecretTree(1, keySchedule.encryptionSecret, cs.kdf)

  return {
    ratchetTree,
    keySchedule,
    secretTree,
    privatePath,
    signaturePrivateKey: privateKeyPackage.signaturePrivateKey,
    unappliedProposals: {},
    historicalResumptionPsks: new Map(),
    groupContext,
    confirmationTag,
  }
}

export async function createProposal(
  state: ClientState,
  publicMessage: boolean,
  proposal: Proposal,
  cs: CiphersuiteImpl,
): Promise<{ newState: ClientState; message: MLSMessage }> {
  const authenticatedData = new Uint8Array()

  if (publicMessage) {
    const result = await protectProposalPublic(
      state.signaturePrivateKey,
      state.keySchedule.membershipKey,
      state.groupContext,
      authenticatedData,
      proposal,
      state.privatePath.leafIndex,
      cs,
    )
    const newState = await processProposal(
      state,
      { content: result.publicMessage.content, auth: result.publicMessage.auth, wireformat: "mls_public_message" },
      proposal,
      cs.hash,
    )
    return {
      newState,
      message: { wireformat: "mls_public_message", version: "mls10", publicMessage: result.publicMessage },
    }
  } else {
    const result = await protectProposal(
      state.signaturePrivateKey,
      state.keySchedule.senderDataSecret,
      proposal,
      authenticatedData,
      state.groupContext,
      state.secretTree,
      state.privatePath.leafIndex,
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
      message: { wireformat: "mls_private_message", version: "mls10", privateMessage: result.privateMessage },
    }
  }
}

export async function createApplicationMessage(state: ClientState, message: Uint8Array, cs: CiphersuiteImpl) {
  if (state.suspendedPendingReinit !== undefined) throw new Error("Group is suspended pending reinit")

  const result = await protectApplicationData(
    state.signaturePrivateKey,
    state.keySchedule.senderDataSecret,
    message,
    new Uint8Array(),
    state.groupContext,
    state.secretTree,
    state.privatePath.leafIndex,
    cs,
  )

  return { newState: { ...state, secretTree: result.newSecretTree }, privateMessage: result.privateMessage }
}

async function exportSecret(
  publicKey: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<{ enc: Uint8Array; secret: Uint8Array }> {
  return cs.hpke.exportSecret(
    await cs.hpke.importPublicKey(publicKey),
    new TextEncoder().encode("MLS 1.0 external init secret"),
    cs.kdf.size,
    new Uint8Array(),
  )
}

async function importSecret(privateKey: Uint8Array, kemOutput: Uint8Array, cs: CiphersuiteImpl): Promise<Uint8Array> {
  return cs.hpke.importSecret(
    await cs.hpke.importPrivateKey(privateKey),
    new TextEncoder().encode("MLS 1.0 external init secret"),
    kemOutput,
    cs.kdf.size,
    new Uint8Array(),
  )
}

export function applyTreeMutations(tree: RatchetTree, grouped: Proposals): [RatchetTree, [number, KeyPackage][]] {
  const treeAfterUpdate = grouped.update.reduce((acc, { senderLeafIndex, proposal }) => {
    if (senderLeafIndex === undefined) throw new Error("No sender index found for update proposal")
    return updateLeafNode(acc, proposal.update.leafNode, senderLeafIndex)
  }, tree)

  const treeAfterRemove = grouped.remove.reduce((acc, { proposal }) => {
    return removeLeafNode(acc, proposal.remove.removed)
  }, treeAfterUpdate)

  const [treeAfterAdd, addedLeafNodes] = grouped.add.reduce(
    (acc, { proposal }) => {
      const [tree, ws] = acc
      const [updatedTree, leafNodeIndex] = addLeafNode(tree, proposal.add.keyPackage.leafNode)
      return [updatedTree, [...ws, [nodeToLeafIndex(leafNodeIndex), proposal.add.keyPackage] as [number, KeyPackage]]]
    },
    [treeAfterRemove, []] as [RatchetTree, [number, KeyPackage][]],
  )

  return [treeAfterAdd, addedLeafNodes]
}
