import { AuthenticationService, CredentialWithKey } from "./authenticationService.js"
import { Capabilities } from "./capabilities.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Signature } from "./crypto/signature.js"
import { defaultExtensionTypes } from "./defaultExtensionType.js"

import { extensionsSupportedByCapabilities, GroupContextExtension, findExtension } from "./extension.js"
import { GroupContext } from "./groupContext.js"
import { KeyPackage, verifyKeyPackage } from "./keyPackage.js"
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
import { validateLifetime } from "./lifetime.js"
import { MlsError, ValidationError, InternalError, CryptoVerificationError, UsageError } from "./mlsError.js"
import { nodeTypes } from "./nodeType.js"
import { verifyParentHashes } from "./parentHash.js"
import { Reinit } from "./proposal.js"
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
} from "./treemath.js"
import { bytesToBase64 } from "./util/byteArray.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"
import { credentialEquals } from "./credential.js"
import { addBatchBuilder, finalizeBatchBuilder, initBatchBuilder } from "./util/batchBuilder.js"
import { chunk } from "./util/array.js"

export async function validateExternalSenders(
  extensions: GroupContextExtension[],
  authService: AuthenticationService,
): Promise<MlsError | undefined> {
  const externalSenders = findExtension(defaultExtensionTypes.external_senders, extensions)
  if (externalSenders !== undefined) {
    const validCredential = await authService.validateCredentialBatch(chunk(externalSenders, authService.batchSize))

    if (validCredential.kind === "error")
      return new ValidationError(`Could not validate external credential: ${validCredential.error}`)
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

  const requiredCapabilities = findExtension(defaultExtensionTypes.required_capabilities, groupContext.extensions)

  if (authService.batchSize < 1) {
    return new UsageError("batchSize should not be less than 1")
  }

  //only authenticate with individual calls if batchSize is 1, otherwise authenticate in batches
  const shouldAuthenticateIndividually = authService.batchSize === 1

  const batchBuilder = initBatchBuilder<CredentialWithKey>(authService.batchSize)

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

      const err =
        n.leaf.leafNodeSource === leafNodeSources.key_package
          ? await validateLeafNodeKeyPackage(
              n.leaf,
              requiredCapabilities,
              false,
              config,
              authService,
              shouldAuthenticateIndividually,
              cs.signature,
            )
          : await validateLeafNodeUpdateOrCommit(
              n.leaf,
              nodeToLeafIndex(nodeIndex),
              requiredCapabilities,
              undefined,
              groupContext,
              authService,
              shouldAuthenticateIndividually,
              cs.signature,
            )

      if (err !== undefined) return err

      if (!shouldAuthenticateIndividually) {
        addBatchBuilder(batchBuilder, { credential: n.leaf.credential, signaturePublicKey: n.leaf.signaturePublicKey })
      }
    } else if (n?.nodeType === nodeTypes.parent) {
      if (isLeaf(nodeIndex)) return new ValidationError("Received Ratchet Tree is not structurally sound")

      const hpkeKey = bytesToBase64(n.parent.hpkePublicKey)
      if (hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")
      else hpkeKeys.add(hpkeKey)

      for (const unmergedLeaf of n.parent.unmergedLeaves) {
        const leafIndex = toLeafIndex(unmergedLeaf)
        const dp = directPath(leafToNodeIndex(leafIndex), leafWidth(tree.length))
        const nodeIndex = leafToNodeIndex(leafIndex)
        if (tree[nodeIndex]?.nodeType !== nodeTypes.leaf || !dp.includes(toNodeIndex(i)))
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

  if (!shouldAuthenticateIndividually) {
    const batches = finalizeBatchBuilder(batchBuilder)

    const authResult = await authService.validateCredentialBatch(batches)

    if (authResult.kind === "error") {
      return new ValidationError(`Could not validate credentials: ${authResult.error}`)
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
async function validateLeafNodeUpdateOrCommit(
  leafNode: LeafNodeCommit | LeafNodeUpdate,
  leafIndex: number,
  requiredCapabilities: RequiredCapabilities | undefined,
  oldLeafNode: LeafNode | undefined,
  groupContext: GroupContext,
  authService: AuthenticationService,
  shouldAuthenticate: boolean,
  s: Signature,
): Promise<MlsError | undefined> {
  const signatureValid = await verifyLeafNodeSignature(leafNode, groupContext.groupId, leafIndex, s)

  if (!signatureValid) return new CryptoVerificationError("Could not verify leaf node signature")

  let requireStandardAuthN = shouldAuthenticate

  if (oldLeafNode && !credentialEquals(oldLeafNode.credential, leafNode.credential)) {
    const validSuccessor = await authService.validateSuccessorCredential(
      { credential: oldLeafNode.credential, signaturePublicKey: oldLeafNode.signaturePublicKey },
      { credential: leafNode.credential, signaturePublicKey: leafNode.signaturePublicKey },
    )
    if (validSuccessor.kind === "error")
      return new ValidationError(`Could not validate credential as successor to existing one: ${validSuccessor.error}`)

    //if we authenticated the new credential as a successor we don't need to authenticate it again
    requireStandardAuthN = false
  }

  const commonError = await validateLeafNodeCommon(leafNode, requiredCapabilities, authService, requireStandardAuthN)

  if (commonError !== undefined) return commonError
}

export function throwIfDefined(err: MlsError | undefined): void {
  if (err !== undefined) throw err
}

async function validateLeafNodeCommon(
  leafNode: LeafNode,
  requiredCapabilities: RequiredCapabilities | undefined,
  authService: AuthenticationService,
  shouldAuthenticate: boolean,
) {
  if (shouldAuthenticate) {
    const credentialValid = await authService.validateCredential(leafNode.credential, leafNode.signaturePublicKey)

    if (credentialValid.kind === "error")
      return new ValidationError(`Could not validate credential: ${credentialValid.error}`)
  }

  if (requiredCapabilities !== undefined) {
    const leafSupportsCapabilities = capabiltiesAreSupported(requiredCapabilities, leafNode.capabilities)

    if (!leafSupportsCapabilities)
      return new ValidationError("Commit contains proposals of member without required capabilities")
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
  shouldAuthenticate: boolean,
  s: Signature,
): Promise<MlsError | undefined> {
  const signatureValid = await verifyLeafNodeSignatureKeyPackage(leafNode, s)
  if (!signatureValid) return new CryptoVerificationError("Could not verify leaf node signature")

  const lifetimeError = validateLifetime(leafNode.lifetime, config, sentByClient)
  if (lifetimeError !== undefined) return lifetimeError

  const commonError = await validateLeafNodeCommon(leafNode, requiredCapabilities, authService, shouldAuthenticate)

  if (commonError !== undefined) return commonError
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
 * Instead when creating a commit call validateLeafNodeLifeTime
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
    true,
    s,
  )
  if (leafNodeError !== undefined) return leafNodeError

  const signatureValid = await verifyKeyPackage(kp, s)
  if (!signatureValid) return new CryptoVerificationError("Invalid keypackage signature")

  if (constantTimeEqual(kp.initKey, kp.leafNode.hpkePublicKey))
    return new ValidationError("Cannot have identicial init and encryption keys")
}

export function validateReinit(reinit: Reinit, gc: GroupContext): ValidationError | undefined {
  if (reinit.version < gc.version)
    return new ValidationError("A ReInit proposal cannot use a version less than the version for the current group")
}
