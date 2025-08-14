import { addHistoricalReceiverData, throwIfDefined, validateRatchetTree } from "./clientState"
import { AuthenticatedContentCommit } from "./authenticatedContent"
import {
  ClientState,
  applyProposals,
  nextEpochContext,
  ApplyProposalsResult,
  exportSecret,
  checkCanSendHandshakeMessages,
  GroupActiveState,
} from "./clientState"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { decryptWithLabel } from "./crypto/hpke"
import { deriveSecret } from "./crypto/kdf"
import {
  createContentCommitSignature,
  createConfirmationTag,
  FramedContentAuthDataCommit,
  FramedContentCommit,
} from "./framedContent"
import { GroupContext, encodeGroupContext } from "./groupContext"
import { GroupInfo, GroupInfoTBS, ratchetTreeFromExtension, signGroupInfo, verifyGroupInfoSignature } from "./groupInfo"
import { KeyPackage, makeKeyPackageRef, PrivateKeyPackage } from "./keyPackage"
import { initializeEpoch, EpochSecrets } from "./keySchedule"
import { MLSMessage } from "./message"
import { protect } from "./messageProtection"
import { protectPublicMessage } from "./messageProtectionPublic"
import { pathToPathSecrets } from "./pathSecrets"
import { mergePrivateKeyPaths, updateLeafKey, toPrivateKeyPath, PrivateKeyPath } from "./privateKeyPath"
import { Proposal, ProposalExternalInit } from "./proposal"
import { ProposalOrRef } from "./proposalOrRefType"
import { PskIndex } from "./pskIndex"
import {
  RatchetTree,
  addLeafNode,
  encodeRatchetTree,
  getCredentialFromLeafIndex,
  getSignaturePublicKeyFromLeafIndex,
  removeLeafNode,
} from "./ratchetTree"
import { createSecretTree, SecretTree } from "./secretTree"
import { treeHashRoot } from "./treeHash"
import { leafWidth, nodeToLeafIndex } from "./treemath"
import { createUpdatePath, PathSecret, firstCommonAncestor, UpdatePath, firstMatchAncestor } from "./updatePath"
import { base64ToBytes } from "./util/byteArray"
import { Welcome, encryptGroupInfo, EncryptedGroupSecrets, encryptGroupSecrets } from "./welcome"
import { CryptoVerificationError, InternalError, UsageError, ValidationError } from "./mlsError"
import { ClientConfig, defaultClientConfig } from "./clientConfig"
import { extensionsSupportedByCapabilities } from "./extension"

export interface CreateCommitResult {
  newState: ClientState
  welcome: Welcome | undefined
  commit: MLSMessage
}

export async function createCommit(
  state: ClientState,
  pskSearch: PskIndex,
  publicMessage: boolean,
  extraProposals: Proposal[],
  cs: CiphersuiteImpl,
  ratchetTreeExtension: boolean = false,
  authenticatedData: Uint8Array = new Uint8Array(),
): Promise<CreateCommitResult> {
  checkCanSendHandshakeMessages(state)

  const wireformat = publicMessage ? "mls_public_message" : "mls_private_message"

  const allProposals = bundleAllProposals(state, extraProposals)

  const res = await applyProposals(state, allProposals, state.privatePath.leafIndex, pskSearch, true, cs)

  if (res.additionalResult.kind === "externalCommit") throw new UsageError("Cannot create externalCommit as a member")

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

  const welcome: Welcome | undefined = await createWelcome(
    ratchetTreeExtension,
    updatedGroupContext,
    confirmationTag,
    state,
    tree,
    cs,
    epochSecrets,
    res,
    pathSecrets,
  )

  const groupActiveState: GroupActiveState = res.selfRemoved
    ? { kind: "removedFromGroup" }
    : suspendedPendingReinit !== undefined
      ? { kind: "suspendedPendingReinit", reinit: suspendedPendingReinit }
      : { kind: "active" }

  const newState: ClientState = {
    groupContext: updatedGroupContext,
    ratchetTree: tree,
    secretTree: await createSecretTree(leafWidth(tree.length), epochSecrets.keySchedule.encryptionSecret, cs.kdf),
    keySchedule: epochSecrets.keySchedule,
    privatePath: privateKeys,
    unappliedProposals: {},
    historicalReceiverData: addHistoricalReceiverData(state),
    confirmationTag,
    signaturePrivateKey: state.signaturePrivateKey,
    groupActiveState,
    clientConfig: state.clientConfig,
  }

  return { newState, welcome, commit }
}

function bundleAllProposals(state: ClientState, extraProposals: Proposal[]): ProposalOrRef[] {
  const refs: ProposalOrRef[] = Object.keys(state.unappliedProposals).map((p) => ({
    proposalOrRefType: "reference",
    reference: base64ToBytes(p),
  }))

  const proposals: ProposalOrRef[] = extraProposals.map((p) => ({ proposalOrRefType: "proposal", proposal: p }))

  return [...refs, ...proposals]
}

async function createWelcome(
  ratchetTreeExtension: boolean,
  groupContext: GroupContext,
  confirmationTag: Uint8Array,
  state: ClientState,
  tree: RatchetTree,
  cs: CiphersuiteImpl,
  epochSecrets: EpochSecrets,
  res: ApplyProposalsResult,
  pathSecrets: PathSecret[],
): Promise<Welcome | undefined> {
  const groupInfo = ratchetTreeExtension
    ? await createGroupInfoWithRatchetTree(groupContext, confirmationTag, state, tree, cs)
    : await createGroupInfo(groupContext, confirmationTag, state, cs)

  const encryptedGroupInfo = await encryptGroupInfo(groupInfo, epochSecrets.welcomeSecret, cs)

  const encryptedGroupSecrets: EncryptedGroupSecrets[] =
    res.additionalResult.kind === "memberCommit"
      ? await Promise.all(
          res.additionalResult.addedLeafNodes.map(([leafNodeIndex, keyPackage]) => {
            return createEncryptedGroupSecrets(
              tree,
              leafNodeIndex,
              state,
              pathSecrets,
              cs,
              keyPackage,
              encryptedGroupInfo,
              epochSecrets,
              res,
            )
          }),
        )
      : []

  return encryptedGroupSecrets.length > 0
    ? {
        cipherSuite: groupContext.cipherSuite,
        secrets: encryptedGroupSecrets,
        encryptedGroupInfo,
      }
    : undefined
}

async function createEncryptedGroupSecrets(
  tree: RatchetTree,
  leafNodeIndex: number,
  state: ClientState,
  pathSecrets: PathSecret[],
  cs: CiphersuiteImpl,
  keyPackage: KeyPackage,
  encryptedGroupInfo: Uint8Array,
  epochSecrets: EpochSecrets,
  res: ApplyProposalsResult,
) {
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

export async function createGroupInfoWithExternalPubAndRatchetTree(
  state: ClientState,
  cs: CiphersuiteImpl,
): Promise<GroupInfo> {
  const gi = await createGroupInfo(state.groupContext, state.confirmationTag, state, cs)

  const encodedTree = encodeRatchetTree(state.ratchetTree)

  const externalKeyPair = await cs.hpke.deriveKeyPair(state.keySchedule.externalSecret)
  const externalPub = await cs.hpke.exportPublicKey(externalKeyPair.publicKey)

  return {
    ...gi,
    extensions: [
      ...gi.extensions,
      { extensionType: "external_pub", extensionData: externalPub },
      { extensionType: "ratchet_tree", extensionData: encodedTree },
    ],
  }
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
      state.clientConfig.paddingConfig,
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

  throw new InternalError("No overlap between provided private keys and update path")
}

export async function joinGroupExternal(
  groupInfo: GroupInfo,
  keyPackage: KeyPackage,
  privateKeys: PrivateKeyPackage,
  resync: boolean,
  cs: CiphersuiteImpl,
  tree?: RatchetTree,
  clientConfig: ClientConfig = defaultClientConfig,
  authenticatedData: Uint8Array = new Uint8Array(),
) {
  const externalPub = groupInfo.extensions.find((ex) => ex.extensionType === "external_pub")

  if (externalPub === undefined) throw new UsageError("Could not find external_pub extension")

  const allExtensionsSupported = extensionsSupportedByCapabilities(
    groupInfo.groupContext.extensions,
    keyPackage.leafNode.capabilities,
  )
  if (!allExtensionsSupported) throw new UsageError("client does not support every extension in the GroupContext")

  const { enc, secret: initSecret } = await exportSecret(externalPub.extensionData, cs)

  const ratchetTree = ratchetTreeFromExtension(groupInfo) ?? tree

  if (ratchetTree === undefined) throw new UsageError("No RatchetTree passed and no ratchet_tree extension")

  throwIfDefined(
    await validateRatchetTree(
      ratchetTree,
      groupInfo.groupContext,
      clientConfig.lifetimeConfig,
      clientConfig.authService,
      groupInfo.groupContext.treeHash,
      cs,
    ),
  )

  const signaturePublicKey = getSignaturePublicKeyFromLeafIndex(ratchetTree, groupInfo.signer)

  const signerCredential = getCredentialFromLeafIndex(ratchetTree, groupInfo.signer)

  const credentialVerified = await clientConfig.authService.validateCredential(signerCredential, signaturePublicKey)

  if (!credentialVerified) throw new ValidationError("Could not validate credential")

  const groupInfoSignatureVerified = verifyGroupInfoSignature(groupInfo, signaturePublicKey, cs.signature)

  if (!groupInfoSignatureVerified) throw new CryptoVerificationError("Could not verify groupInfo Signature")

  const formerLeafIndex = resync
    ? nodeToLeafIndex(
        ratchetTree.findIndex((n) => {
          if (n !== undefined && n.nodeType === "leaf") {
            return clientConfig.keyPackageEqualityConfig.compareKeyPackageToLeafNode(keyPackage, n.leaf)
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
      ? new Uint8Array(cs.kdf.size)
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
    authenticatedData,
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
    historicalReceiverData: new Map(),
    signaturePrivateKey: privateKeys.signaturePrivateKey,
    keySchedule: epochSecrets.keySchedule,
    unappliedProposals: {},
    groupActiveState: { kind: "active" },
    clientConfig,
  }

  const authenticatedContent: AuthenticatedContentCommit = {
    content: framedContent,
    auth: { signature, confirmationTag, contentType: "commit" },
    wireformat: "mls_public_message",
  }

  const msg = await protectPublicMessage(epochSecrets.keySchedule.membershipKey, groupContext, authenticatedContent, cs)

  return { publicMessage: msg, newState: state }
}
export function filterNewLeaves(resolution: number[], excludeNodes: number[]): number[] {
  const set = new Set(excludeNodes)
  return resolution.filter((i) => !set.has(i))
}
