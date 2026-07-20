import { AuthenticationService } from "./authenticationService.js"
import { Capabilities } from "./capabilities.js"
import { GroupedProposals, flattenExtensions } from "./groupedProposals.js"
import { encode } from "./codec/tlsEncoder.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Signature } from "./crypto/signature.js"
import { defaultExtensionTypes } from "./defaultExtensionType.js"
import { defaultProposalTypes } from "./defaultProposalType.js"
import {
  extensionsSupportedByCapabilities,
  GroupContextExtension,
  ExtensionExternalSenders,
  findRequiredCapabilities,
} from "./extension.js"
import { GroupContext } from "./groupContext.js"
import { KeyPackage, verifyKeyPackage } from "./keyPackage.js"
import { KeyPackageEqualityConfig } from "./keyPackageEqualityConfig.js"
import {
  LeafNodeCommit,
  LeafNodeUpdate,
  verifyLeafNodeSignature,
  LeafNode,
  LeafNodeKeyPackage,
  verifyLeafNodeSignatureKeyPackage,
} from "./leafNode.js"
import { leafNodeSources } from "./leafNodeSource.js"
import { LifetimeConfig } from "./lifetimeConfig.js"
import { MlsError, ValidationError, InternalError, CryptoVerificationError } from "./mlsError.js"
import { nodeTypes } from "./nodeType.js"
import { verifyParentHashes } from "./parentHash.js"
import { pskIdEncoder } from "./presharedkey.js"
import { Reinit, Remove } from "./proposal.js"
import { RatchetTree } from "./ratchetTree.js"
import { RequiredCapabilities } from "./requiredCapabilities.js"
import { TreeHashCache, treeHashRoot } from "./treeHash.js"
import {
  nodeToLeafIndex,
  toNodeIndex,
  isLeaf,
  toLeafIndex,
  directPath,
  leafToNodeIndex,
  leafWidth,
  LeafIndex,
} from "./treemath.js"
import { ProposalWithSender } from "./unappliedProposals.js"
import { bytesToBase64 } from "./util/byteArray.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"
import { credentialEquals } from "./credential.js"
import { UpdatePathNode } from "./updatePath.js"

/*
 * For Leaf Node Validation purposes we define the following two sub-validations:
 * - 7.3.y Verify that the credential type is supported by all members of the group,
 *   as specified by the capabilities field of each member's LeafNode,
 *   and that the capabilities field of this LeafNode indicates support for all the credential types currently in use by other members.
 * - 7.3.z Verify that the following fields are unique among the members of the group:
 *         signature_key
 *         encryption_key
 * These are important because they require checking the entire tree, so we want to ensure we don't traverse the tree multiple times.
 */

/**
 * Validates a full list of proposals (excluding external_init), used when creating or receiving a commit.
 * When receiving a commit, sentByClient needs to be false.
 */
export async function validateProposals(
  p: GroupedProposals,
  committerLeafIndex: number | undefined,
  groupContext: GroupContext,
  config: KeyPackageEqualityConfig,
  lifetimeConfig: LifetimeConfig,
  authService: AuthenticationService,
  sentByClient: boolean,
  tree: RatchetTree,
  cs: CiphersuiteImpl,
): Promise<MlsError | undefined> {
  const containsUpdateByCommitter = p[defaultProposalTypes.update].some(
    (o) => o.senderLeafIndex !== undefined && o.senderLeafIndex === committerLeafIndex,
  )

  if (containsUpdateByCommitter)
    return new ValidationError("Commit cannot contain an update proposal sent by committer")

  const containsRemoveOfCommitter = p[defaultProposalTypes.remove].some(
    (o) => o.proposal.remove.removed === committerLeafIndex,
  )

  if (containsRemoveOfCommitter)
    return new ValidationError("Commit cannot contain a remove proposal removing committer")

  const multipleUpdateRemoveForSameLeaf =
    p[defaultProposalTypes.update].some(
      ({ senderLeafIndex: a }, indexA) =>
        p[defaultProposalTypes.update].some(({ senderLeafIndex: b }, indexB) => a === b && indexA !== indexB) ||
        p[defaultProposalTypes.remove].some((r) => r.proposal.remove.removed === a),
    ) ||
    p[defaultProposalTypes.remove].some(
      (a, indexA) =>
        p[defaultProposalTypes.remove].some(
          (b, indexB) => b.proposal.remove.removed === a.proposal.remove.removed && indexA !== indexB,
        ) ||
        p[defaultProposalTypes.update].some(({ senderLeafIndex }) => a.proposal.remove.removed === senderLeafIndex),
    )

  if (multipleUpdateRemoveForSameLeaf)
    return new ValidationError(
      "Commit cannot contain multiple update and/or remove proposals that apply to the same leaf",
    )

  const multipleAddsContainSameKeypackage = p[defaultProposalTypes.add].some(({ proposal: a }, indexA) =>
    p[defaultProposalTypes.add].some(
      ({ proposal: b }, indexB) => config.compareKeyPackages(a.add.keyPackage, b.add.keyPackage) && indexA !== indexB,
    ),
  )

  if (multipleAddsContainSameKeypackage)
    return new ValidationError(
      "Commit cannot contain multiple Add proposals that contain KeyPackages that represent the same client",
    )

  const multipleGroupContextExtensions = p[defaultProposalTypes.group_context_extensions].length > 1

  if (multipleGroupContextExtensions)
    return new ValidationError("Commit cannot contain multiple GroupContextExtensions proposals")

  const allExtensions = flattenExtensions(p[defaultProposalTypes.group_context_extensions]) ?? []

  //From the spec:
  // A GroupContextExtensions proposal is invalid if it includes a required_capabilities extension and some members of the group do not support some of the required capabilities
  // (including those added in the same Commit, and excluding those removed).
  // if a GroupContextExtensions proposal adds a required_capabilities extension, then any Add proposals need to indicate support for those capabilities.
  const requiredCapabilities =
    findRequiredCapabilities(allExtensions) ?? findRequiredCapabilities(groupContext.extensions)

  const validateRemoveError = findMap(p[defaultProposalTypes.remove], (n) => validateRemove(n.proposal.remove, tree))
  if (validateRemoveError) return validateRemoveError

  const allNewLeafNodes = collectProposalLeafNodes(p)

  if (!sentByClient) {
    for (const ap of allNewLeafNodes) {
      if (ap.kind === "add") {
        const validateKeyPackageError = await validateKeyPackage(
          ap.keyPackage,
          groupContext,
          requiredCapabilities,
          false,
          lifetimeConfig,
          authService,
          cs.signature,
        )

        if (validateKeyPackageError) return validateKeyPackageError
      } else {
        const senderLeafIndex = ap.senderLeafIndex
        const leafNodeIndex = leafToNodeIndex(senderLeafIndex)
        const oldLeafNode = tree[leafNodeIndex]
        if (oldLeafNode?.nodeType !== nodeTypes.leaf) throw new InternalError("Tried to update a non-leaf node")

        const validateLeafNodeError = await validateLeafNodeUpdateOrCommit(
          ap.leafNode,
          senderLeafIndex,
          requiredCapabilities,
          oldLeafNode.leaf,
          groupContext,
          authService,
          cs.signature,
        )

        if (validateLeafNodeError) return validateLeafNodeError
      }
    }
  }

  const leafNodeCredentialInvalidOrKeyNotUnique = await validateLeafNodeCredentialAndKeyUniqueness(
    tree,
    allNewLeafNodes,
    config,
    requiredCapabilities,
  )

  if (leafNodeCredentialInvalidOrKeyNotUnique) return leafNodeCredentialInvalidOrKeyNotUnique

  const everyLeafSupportsGroupExtensions = p[defaultProposalTypes.add].every(({ proposal }) =>
    extensionsSupportedByCapabilities(groupContext.extensions, proposal.add.keyPackage.leafNode.capabilities),
  )

  if (!everyLeafSupportsGroupExtensions)
    return new ValidationError("Added leaf node that doesn't support extension in GroupContext")

  const multiplePskWithSamePskId = p[defaultProposalTypes.psk].some((a, indexA) =>
    p[defaultProposalTypes.psk].some(
      (b, indexB) =>
        constantTimeEqual(
          encode(pskIdEncoder, a.proposal.psk.preSharedKeyId),
          encode(pskIdEncoder, b.proposal.psk.preSharedKeyId),
        ) && indexA !== indexB,
    ),
  )

  if (multiplePskWithSamePskId)
    return new ValidationError("Commit cannot contain PreSharedKey proposals that reference the same PreSharedKeyID")

  return await validateExternalSenders(allExtensions, authService)
}

function collectProposalLeafNodes(p: GroupedProposals): NewLeafNodeWithSender[] {
  const allNewLeafNodes: NewLeafNodeWithSender[] = []

  for (const { proposal } of p[defaultProposalTypes.add]) {
    allNewLeafNodes.push({ kind: "add", keyPackage: proposal.add.keyPackage })
  }

  for (const update of p[defaultProposalTypes.update]) {
    allNewLeafNodes.push({
      kind: "update",
      leafNode: update.proposal.update.leafNode,
      senderLeafIndex: update.senderLeafIndex,
      updatePath: undefined,
    })
  }
  return allNewLeafNodes
}

export async function validateExternalSenders(
  extensions: GroupContextExtension[],
  authService: AuthenticationService,
): Promise<MlsError | undefined> {
  const externalSenders = extensions.find(
    (e): e is ExtensionExternalSenders => e.extensionType === defaultExtensionTypes.external_senders,
  )
  if (externalSenders) {
    for (const externalSender of externalSenders.extensionData) {
      const validCredential = await authService.validateCredential(
        externalSender.credential,
        externalSender.signaturePublicKey,
      )
      if (!validCredential) return new ValidationError("Could not validate external credential")
    }
  }
}
function capabiltiesAreSupported(caps: RequiredCapabilities, cs: Capabilities): boolean {
  return (
    caps.credentialTypes.every((c) => cs.credentials.includes(c)) &&
    caps.extensionTypes.every((e) => cs.extensions.includes(e)) &&
    caps.proposalTypes.every((p) => cs.proposals.includes(p))
  )
}

/**
 * Validates entire ratchetTree, as instructed by section 12.4.3.1:
 * Verify that the tree hash of the ratchet tree matches the tree_hash field in GroupInfo.
 * For each non-empty parent node, verify that it is "parent-hash valid", as described in Section 7.9.2.
 * For each non-empty leaf node, validate the LeafNode as described in Section 7.3.
 * For each non-empty parent node and each entry in the node's unmerged_leaves field:
 *    Verify that the entry represents a non-blank leaf node that is a descendant of the parent node.
 *    Verify that every non-blank intermediate node between the leaf node and the parent node also has an entry for the leaf node in its unmerged_leaves.
 *    Verify that the encryption key in the parent node does not appear in any other node of the tree.
 */
export async function validateRatchetTree(
  tree: RatchetTree,
  groupContext: GroupContext,
  config: LifetimeConfig,
  authService: AuthenticationService,
  treeHash: Uint8Array,
  cs: CiphersuiteImpl,
  mutableTreeHashCache?: TreeHashCache,
): Promise<MlsError | undefined> {
  const cache = mutableTreeHashCache ?? []
  const hpkeKeys = new Set<string>()
  const signatureKeys = new Set<string>()
  const credentialTypes = new Set<number>()

  const requiredCapabilities = findRequiredCapabilities(groupContext.extensions)

  for (const [i, n] of tree.entries()) {
    const nodeIndex = toNodeIndex(i)
    if (n?.nodeType === nodeTypes.leaf) {
      if (!isLeaf(nodeIndex)) return new ValidationError("Received Ratchet Tree is not structurally sound")

      const hpkeKey = bytesToBase64(n.leaf.hpkePublicKey)
      if (hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")
      else hpkeKeys.add(hpkeKey)

      const signatureKey = bytesToBase64(n.leaf.signaturePublicKey)
      if (signatureKeys.has(signatureKey)) return new ValidationError("signature keys not unique")
      else signatureKeys.add(signatureKey)

      credentialTypes.add(n.leaf.credential.credentialType)

      //TODO this will validate all leafNodes sequentially, consider parallelizing with configurable parallelism or allow authenticating in batches
      const err =
        n.leaf.leafNodeSource === leafNodeSources.key_package
          ? await validateLeafNodeKeyPackage(n.leaf, requiredCapabilities, false, config, authService, cs.signature)
          : await validateLeafNodeUpdateOrCommit(
              n.leaf,
              nodeToLeafIndex(nodeIndex),
              requiredCapabilities,
              undefined,
              groupContext,
              authService,
              cs.signature,
            )

      if (err !== undefined) return err
    } else if (n?.nodeType === nodeTypes.parent) {
      if (isLeaf(nodeIndex)) return new ValidationError("Received Ratchet Tree is not structurally sound")

      const hpkeKey = bytesToBase64(n.parent.hpkePublicKey)
      if (hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")
      else hpkeKeys.add(hpkeKey)

      for (const unmergedLeaf of n.parent.unmergedLeaves) {
        const leafIndex = toLeafIndex(unmergedLeaf)
        const dp = directPath(leafToNodeIndex(leafIndex), leafWidth(tree.length))
        const nodeIndex = leafToNodeIndex(leafIndex)
        if (tree[nodeIndex]?.nodeType !== nodeTypes.leaf && !dp.includes(toNodeIndex(i)))
          return new ValidationError("Unmerged leaf did not represent a non-blank descendant leaf node")

        for (const parentIdx of dp) {
          if (parentIdx === toNodeIndex(i)) break
          const dpNode = tree[parentIdx]

          if (dpNode !== undefined) {
            if (dpNode.nodeType !== nodeTypes.parent) return new InternalError("Expected parent node")

            if (!dpNode.parent.unmergedLeaves.includes(unmergedLeaf))
              return new ValidationError("non-blank intermediate node must list leaf node in its unmerged_leaves")
          }
        }
      }
    }
  }

  //TODO instead of traversing the entire tree twice we could just collect the capabilities in the prior iteration and ensure the intersection is valid?
  for (const n of tree) {
    if (n?.nodeType === nodeTypes.leaf) {
      for (const credentialType of credentialTypes) {
        if (!n.leaf.capabilities.credentials.includes(credentialType))
          return new ValidationError("LeafNode has credential that is not supported by member of the group")
      }
    }
  }

  const parentHashesVerified = await verifyParentHashes(tree, cs.hash, cache)

  if (!parentHashesVerified) return new CryptoVerificationError("Unable to verify parent hash")

  if (!constantTimeEqual(treeHash, await treeHashRoot(tree, cs.hash, cache)))
    return new ValidationError("Unable to verify tree hash")
}

/**
 * Verifies a LeafNode according to section 7.3.
 * Crucially it does not include 7.3.y and 7.3.z
 *
 * This covers the following cases from 7.3:
 *   When a LeafNode is received by a group member in an [..] Update, or Commit message
 *   When a client validates a ratchet tree, e.g., when joining a group or after processing a Commit
 *
 * This doesn't need to be called when a commit is being created!
 */
export async function validateLeafNodeUpdateOrCommit(
  leafNode: LeafNodeCommit | LeafNodeUpdate,
  leafIndex: number,
  requiredCapabilities: RequiredCapabilities | undefined,
  oldLeafNode: LeafNode | undefined,
  groupContext: GroupContext,
  authService: AuthenticationService,
  s: Signature,
): Promise<MlsError | undefined> {
  const signatureValid = await verifyLeafNodeSignature(leafNode, groupContext.groupId, leafIndex, s)

  if (!signatureValid) return new CryptoVerificationError("Could not verify leaf node signature")

  const commonError = await validateLeafNodeCommon(leafNode, requiredCapabilities, authService)

  if (commonError !== undefined) return commonError

  if (oldLeafNode && !credentialEquals(oldLeafNode.credential, leafNode.credential)) {
    const validSuccessor = await authService.validateSuccessorCredential(oldLeafNode.credential, leafNode.credential)
    if (!validSuccessor) return new ValidationError("Could not validate credential as successor to existing one")
  }
}

export function throwIfDefined(err: MlsError | undefined): void {
  if (err !== undefined) throw err
}

async function validateLeafNodeCommon(
  leafNode: LeafNode,
  requiredCapabilities: RequiredCapabilities | undefined,
  authService: AuthenticationService,
) {
  const credentialValid = await authService.validateCredential(leafNode.credential, leafNode.signaturePublicKey)

  if (!credentialValid) return new ValidationError("Could not validate credential")

  if (requiredCapabilities !== undefined) {
    const leafSupportsCapabilities = capabiltiesAreSupported(requiredCapabilities, leafNode.capabilities)

    if (!leafSupportsCapabilities) return new ValidationError("LeafNode does not support required capabilities")
  }

  const extensionsSupported = extensionsSupportedByCapabilities(leafNode.extensions, leafNode.capabilities)

  if (!extensionsSupported) return new ValidationError("LeafNode contains extension not listed in capabilities")
}

/**
 * Verifies a LeafNode according to section 7.3.
 * Crucially it does not include 7.3.y and 7.3.z
 *
 * This covers the following cases from 7.3:
 *   When a LeafNode is downloaded in a KeyPackage, before it is used to add the client to the group
 *   When a LeafNode is received by a group member in an Add [..] message
 *   When a client validates a ratchet tree, e.g., when joining a group or after processing a Commit
 *
 * This doesn't need to be called when a commit is being created!
 */
async function validateLeafNodeKeyPackage(
  leafNode: LeafNodeKeyPackage,
  requiredCapabilities: RequiredCapabilities | undefined,
  sentByClient: boolean,
  config: LifetimeConfig,
  authService: AuthenticationService,
  s: Signature,
): Promise<MlsError | undefined> {
  const signatureValid = await verifyLeafNodeSignatureKeyPackage(leafNode, s)
  if (!signatureValid) return new CryptoVerificationError("Could not verify leaf node signature")

  //verify lifetime
  if (sentByClient || config.validateLifetimeOnReceive) {
    if (leafNode.leafNodeSource === leafNodeSources.key_package) {
      const currentTime = BigInt(Math.floor(Date.now() / 1000))
      if (leafNode.lifetime.notBefore > currentTime || leafNode.lifetime.notAfter < currentTime)
        return new ValidationError("Current time not within Lifetime")
    }
  }

  const commonError = await validateLeafNodeCommon(leafNode, requiredCapabilities, authService)

  if (commonError !== undefined) return commonError
}

export type NewLeafNodeWithSender =
  | {
      kind: "update"
      leafNode: LeafNodeUpdate | LeafNodeCommit
      senderLeafIndex: LeafIndex
      updatePath: UpdatePathNode[] | undefined
    }
  | {
      kind: "add"
      keyPackage: KeyPackage
    }

function extractLeafNode(p: NewLeafNodeWithSender): LeafNode {
  if (p.kind === "add") {
    return p.keyPackage.leafNode
  }

  return p.leafNode
}

// interface NewNode {
//   hpkeKey: Uint8Array,
//   signatureKeyAndLeafIndex?: [Uint8Array, LeafIndex | null],
//   capabilities?: Capabilities
//   credentialType?: number
//   senderLeafIndex?: LeafIndex
//   keyPackage?: KeyPackage
// }

export async function validateLeafNodeCredentialAndKeyUniqueness(
  tree: RatchetTree,
  proposalsWithSenders: NewLeafNodeWithSender[],
  config: KeyPackageEqualityConfig,
  requiredCaps: RequiredCapabilities | undefined,
): Promise<ValidationError | undefined> {
  const credentialTypes = new Set<number>()
  const hpkeKeys = new Set<string>()
  const signatureKeys = new Map<string, LeafIndex | null>()
  const keyPackages = new Array<KeyPackage>()

  for (const nln of proposalsWithSenders) {
    const ln = extractLeafNode(nln)
    credentialTypes.add(ln.credential.credentialType)
    hpkeKeys.add(bytesToBase64(ln.hpkePublicKey))
    signatureKeys.set(bytesToBase64(ln.signaturePublicKey), nln.kind === "update" ? nln.senderLeafIndex : null)

    if (nln.kind === "add") {
      keyPackages.push(nln.keyPackage)
    } else if (nln.updatePath) {
      for (const pathNode of nln.updatePath) {
        hpkeKeys.add(bytesToBase64(pathNode.hpkePublicKey))
      }
    }

    if (requiredCaps) {
      if (!capabiltiesAreSupported(requiredCaps, ln.capabilities)) {
        return new ValidationError("Commit contains proposals of member without required capabilities")
      }
    }
  }

  for (const [nodeIndex, node] of tree.entries()) {
    if (node?.nodeType === nodeTypes.leaf) {
      //the credential capabilities should include all input credentialTypes
      if (!isSubset(credentialTypes, node.leaf.capabilities.credentials)) {
        return new ValidationError("LeafNode has credential that is not supported by member of the group")
      }

      const keyPackageMatch = keyPackages.some((kp) => config.compareKeyPackageToLeafNode(kp, node.leaf))
      if (keyPackageMatch) {
        return new ValidationError("Commit cannot contain an Add proposal for someone already in the group")
      }

      const hpkeKey = bytesToBase64(node.leaf.hpkePublicKey)
      if (hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")

      const signatureKey = bytesToBase64(node.leaf.signaturePublicKey)
      const signatureMatch = signatureKeys.get(signatureKey)

      if (signatureMatch === null) {
        //match will be null iff the leafNode is being added, not updated, so if it's null it's definitely an error
        return new ValidationError("signature keys not unique")
      } else if (signatureMatch !== undefined && signatureMatch !== nodeToLeafIndex(toNodeIndex(nodeIndex))) {
        // match is not undefined but not equal to the current node, so it's an update but to a different node therefore an error
        return new ValidationError("signature keys not unique")
      }

      if (requiredCaps) {
        if (!capabiltiesAreSupported(requiredCaps, node.leaf.capabilities)) {
          return new ValidationError("Not all members support required capabilities")
        }
      }
    } else if (node?.nodeType === nodeTypes.parent) {
      const hpkeKey = bytesToBase64(node.parent.hpkePublicKey)
      if (hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")
    }
  }
}

function isSubset(a: ReadonlySet<number>, b: readonly number[]): boolean {
  if (a.size > b.length) return false

  for (const x of a) {
    if (!b.includes(x)) {
      return false
    }
  }

  return true
}

/**
 * Validates a KeyPackage according to section 10.1.:
 * The validity of a KeyPackage needs to be verified at a few stages:
 *   When a KeyPackage is downloaded by a group member, before it is used to add the client to the group
 *   When a KeyPackage is received by a group member in an Add message
 * Includes 7.3. Leaf Node Validation.
 *
 * Crucially, it doesn't contain 7.3.y and 7.3.z
 *
 * This does not need to be called when creating a commit!
 */
export async function validateKeyPackage(
  kp: KeyPackage,
  groupContext: GroupContext,
  requiredCapabilities: RequiredCapabilities | undefined,
  sentByClient: boolean,
  config: LifetimeConfig,
  authService: AuthenticationService,
  s: Signature,
): Promise<MlsError | undefined> {
  if (kp.cipherSuite !== groupContext.cipherSuite) return new ValidationError("Invalid CipherSuite")

  if (kp.version !== groupContext.version) return new ValidationError("Invalid mls version")

  const leafNodeError = await validateLeafNodeKeyPackage(
    kp.leafNode,
    requiredCapabilities,
    sentByClient,
    config,
    authService,
    s,
  )
  if (leafNodeError !== undefined) return leafNodeError

  const signatureValid = await verifyKeyPackage(kp, s)
  if (!signatureValid) return new CryptoVerificationError("Invalid keypackage signature")

  if (constantTimeEqual(kp.initKey, kp.leafNode.hpkePublicKey))
    return new ValidationError("Cannot have identicial init and encryption keys")
}

export function validateReinit(
  allProposals: ProposalWithSender[],
  reinit: Reinit,
  gc: GroupContext,
): ValidationError | undefined {
  if (allProposals.length !== 1) return new ValidationError("Reinit proposal needs to be commited by itself")

  if (reinit.version < gc.version)
    return new ValidationError("A ReInit proposal cannot use a version less than the version for the current group")
}

export function validateExternalInit(grouped: GroupedProposals): ValidationError | undefined {
  if (grouped[defaultProposalTypes.external_init].length > 1)
    return new ValidationError("Cannot contain more than one external_init proposal")

  if (grouped[defaultProposalTypes.remove].length > 1)
    return new ValidationError("Cannot contain more than one remove proposal")

  if (
    grouped[defaultProposalTypes.add].length > 0 ||
    grouped[defaultProposalTypes.group_context_extensions].length > 0 ||
    grouped[defaultProposalTypes.reinit].length > 0 ||
    grouped[defaultProposalTypes.update].length > 0
  )
    return new ValidationError("Invalid proposals")
}

function validateRemove(remove: Remove, tree: RatchetTree): MlsError | undefined {
  if (tree[leafToNodeIndex(toLeafIndex(remove.removed))] === undefined)
    return new ValidationError("Tried to remove empty leaf node")
}

function findMap<T, U>(items: readonly T[], fn: (item: T) => U | undefined): U | undefined {
  for (const item of items) {
    const result = fn(item)
    if (result !== undefined) {
      return result
    }
  }
  return undefined
}
