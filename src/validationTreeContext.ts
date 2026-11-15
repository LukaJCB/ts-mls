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

import { KeyPackageEqualityConfig } from "./keyPackageEqualityConfig.js"
import { RatchetTree } from "./ratchetTree.js"
import { RequiredCapabilities } from "./requiredCapabilities.js"
import { throwIfDefined } from "./validation.js"
import { LeafIndex, nodeToLeafIndex, toNodeIndex } from "./treemath.js"
import { KeyPackage } from "./keyPackage.js"
import { bytesToBase64, fastEqual } from "./util/byteArray.js"
import { capabiltiesAreSupported, validateKeyPackage, validateLeafNodeUpdateOrCommit } from "./validationStructural.js"
import { LeafNode } from "./leafNode.js"
import { nodeTypes } from "./nodeType.js"
import { AuthenticationService, CredentialBatchItem } from "./authenticationService.js"
import { addBatchBuilder, finalizeBatchBuilder, initBatchBuilder } from "./util/batchBuilder.js"
import { ExternalSender } from "./externalSender.js"
import { UpdatePathNode } from "./updatePath.js"
import { ValidationError } from "./mlsError.js"
import { LeafChange } from "./leafChange.js"
import { ClientConfig } from "./clientConfig.js"
import { Signature } from "./crypto/signature.js"
import { GroupContext } from "./groupContext.js"
import { extensionsSupportedByCapabilities, GroupContextExtension } from "./extension.js"

export type AuthIndices = {
  authInput: CredentialBatchItem[][]
  treeIndexes: TreeValidationIndexes
}

export interface TreeValidationIndexes {
  proposedCredentialTypes: ReadonlySet<number>
  hpkeKeys: ReadonlySet<string>
  signatureKeys: ReadonlyMap<string, LeafIndex | null>
}

export interface ParsedGroupContextExtensions {
  groupContextExtensions: GroupContextExtension[]
  authenticated: boolean
  newExternalSenders: ExternalSender[] | undefined
  newRequiredCapabilities: RequiredCapabilities | undefined
}

export interface LeafValidationInput {
  adds: readonly {
    keyPackage: KeyPackage
    authenticated: boolean
    sentByClient: boolean
  }[]
  leafChanges: Map<LeafIndex, LeafChange>
  removals: Set<LeafIndex>

  groupContextExtensions: ParsedGroupContextExtensions | undefined
}

/**
 * This function validates new leafNodes and checks them for structural integrity, and that they support any requiredCapabilities.
 *  Gets all hpke keys, signature keys, keypackages and credential types from the input for later validation
 */
export async function validateProposalsExtractAuthIndices(
  leafValidationInput: LeafValidationInput,
  updatePathNodes: UpdatePathNode[] | undefined,
  requiredCaps: RequiredCapabilities | undefined,
  groupContext: GroupContext,
  effectiveGroupContextExtensions: GroupContextExtension[],
  config: ClientConfig,
  batchSize: number,
  s: Signature,
): Promise<AuthIndices> {
  const proposedCredentialTypes = new Set<number>()
  const hpkeKeys = new Set<string>()
  const signatureKeys = new Map<string, LeafIndex | null>()

  const credentialBatchBuilder = initBatchBuilder<CredentialBatchItem>(batchSize)

  if (
    leafValidationInput.groupContextExtensions?.newExternalSenders !== undefined &&
    !leafValidationInput.groupContextExtensions.authenticated
  ) {
    for (const externalSender of leafValidationInput.groupContextExtensions.newExternalSenders) {
      addBatchBuilder(credentialBatchBuilder, externalSender)
    }
  }

  for (const [index, add] of leafValidationInput.adds.entries()) {
    throwIfDefined(
      await validateKeyPackage(add.keyPackage, groupContext, requiredCaps, add.sentByClient, config.lifetimeConfig, s),
    )
    const ln = add.keyPackage.leafNode
    //TODO are we checking requiredCaps twice here? we should probably remove it from one of them
    addCredentialsAndKeysCheckSupport(
      proposedCredentialTypes,
      ln,
      hpkeKeys,
      requiredCaps,
      effectiveGroupContextExtensions,
    )

    const stringKey = bytesToBase64(ln.signaturePublicKey)
    if (signatureKeys.has(stringKey)) throw new ValidationError("Duplicate signature key")
    signatureKeys.set(stringKey, null)

    for (let x = 0; x < index; x++) {
      if (config.keyPackageEqualityConfig.compareKeyPackages(leafValidationInput.adds[x]!.keyPackage, add.keyPackage)) {
        throw new ValidationError("Duplicate keyPackage in add proposals")
      }
    }
    if (!add.authenticated) {
      addBatchBuilder(credentialBatchBuilder, ln)
    }
  }

  for (const [senderLeafIndex, update] of leafValidationInput.leafChanges.entries()) {
    const ln = update.newLeafNode
    throwIfDefined(
      await validateLeafNodeUpdateOrCommit(update.newLeafNode, senderLeafIndex, requiredCaps, groupContext, s),
    )

    addCredentialsAndKeysCheckSupport(
      proposedCredentialTypes,
      ln,
      hpkeKeys,
      requiredCaps,
      effectiveGroupContextExtensions,
    )

    if (update.oldLeafNode !== undefined && fastEqual(ln.hpkePublicKey, update.oldLeafNode.hpkePublicKey)) {
      throw new ValidationError("Updated LeafNode cannot have the same HPKE key")
    }

    const stringKey = bytesToBase64(ln.signaturePublicKey)
    if (signatureKeys.has(stringKey)) throw new ValidationError("Duplicate signature key")
    signatureKeys.set(bytesToBase64(ln.signaturePublicKey), senderLeafIndex)

    const oldCredential =
      update.oldLeafNode !== undefined
        ? { credential: update.oldLeafNode.credential, signaturePublicKey: update.oldLeafNode.signaturePublicKey }
        : undefined

    if (!update.authenticated) {
      addBatchBuilder(credentialBatchBuilder, {
        credential: ln.credential,
        signaturePublicKey: ln.signaturePublicKey,
        oldCredential,
      })
    }
  }

  if (updatePathNodes !== undefined) {
    for (const pathItem of updatePathNodes) {
      const stringKey = bytesToBase64(pathItem.hpkePublicKey)
      if (hpkeKeys.has(stringKey)) throw new ValidationError("Duplicate HPKE key in update path")
      hpkeKeys.add(bytesToBase64(pathItem.hpkePublicKey))
    }
  }

  for (const add of leafValidationInput.adds) {
    //1.3.1 check that the leafNodes in add Proposals support proposedCredentialTypes
    if (!isSubset(proposedCredentialTypes, add.keyPackage.leafNode.capabilities.credentials)) {
      throw new ValidationError("Proposals include leafNode that doesn't support a proposed leafNode's credentialType")
    }
  }

  for (const update of leafValidationInput.leafChanges.values()) {
    //1.3.2 check that the leafNodes in update Proposals or updated commiter leaf support proposedCredentialTypes
    if (!isSubset(proposedCredentialTypes, update.newLeafNode.capabilities.credentials)) {
      throw new ValidationError("Proposals include leafNode that doesn't support a proposed leafNode's credentialType")
    }
  }

  return {
    treeIndexes: { proposedCredentialTypes, hpkeKeys, signatureKeys },
    authInput: finalizeBatchBuilder(credentialBatchBuilder),
  }
}

function addCredentialsAndKeysCheckSupport(
  credentialTypes: Set<number>,
  ln: LeafNode,
  hpkeKeys: Set<string>,
  requiredCaps: RequiredCapabilities | undefined,
  effectiveExtensions: GroupContextExtension[],
) {
  credentialTypes.add(ln.credential.credentialType)

  const stringKey = bytesToBase64(ln.hpkePublicKey)
  if (hpkeKeys.has(stringKey)) throw new ValidationError("Duplicate HPKE public key")
  hpkeKeys.add(stringKey)

  if (requiredCaps) {
    if (!capabiltiesAreSupported(requiredCaps, ln.capabilities)) {
      throw new ValidationError("Commit contains proposals of member without required capabilities")
    }
  }

  if (!extensionsSupportedByCapabilities(effectiveExtensions, ln.capabilities)) {
    throw new ValidationError("LeafNode does not support GroupContext extensions")
  }
}

/**
 * This function validates new leafNodes and checks that they support any requiredCapabilities.
 * Validates key uniqueness, capabilites, etc.
 */
export function validateProposalsAgainstFullTree(
  tree: RatchetTree,
  input: TreeValidationIndexes,
  proposals: LeafValidationInput,
  config: KeyPackageEqualityConfig,
  removals: Set<LeafIndex>,
  newGroupContextExtensions:
    | { groupContextExtensions: GroupContextExtension[]; newRequiredCapabilities: RequiredCapabilities | undefined }
    | undefined,
): ValidationError | undefined {
  const existingCredentialTypes = new Set<number>()
  for (const [nodeIndex, node] of tree.entries()) {
    const leafIndex = nodeToLeafIndex(toNodeIndex(nodeIndex))
    if (node?.nodeType === nodeTypes.leaf) {
      if (!removals.has(leafIndex)) {
        const leafChange = proposals.leafChanges.get(leafIndex)

        if (leafChange === undefined) {
          const hpkeKey = bytesToBase64(node.leaf.hpkePublicKey)
          if (input.hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")

          const signatureKey = bytesToBase64(node.leaf.signaturePublicKey)
          const signatureMatch = input.signatureKeys.get(signatureKey)

          if (signatureMatch === null) {
            //match will be null iff the leafNode is being added, not updated, so if it's null it's definitely an error
            return new ValidationError("signature keys not unique")
          } else if (signatureMatch !== undefined && signatureMatch !== leafIndex) {
            // match is not undefined but not equal to the current node, so it's an update but to a different node therefore an error
            return new ValidationError("signature keys not unique")
          }

          //1.2 new/updated credentialTypes need to be supported by all existing (non removed/replaced) members
          if (!isSubset(input.proposedCredentialTypes, node.leaf.capabilities.credentials)) {
            return new ValidationError("LeafNode has credential that is not supported by member of the group")
          }

          if (newGroupContextExtensions !== undefined) {
            if (
              !extensionsSupportedByCapabilities(
                newGroupContextExtensions.groupContextExtensions,
                node.leaf.capabilities,
              )
            ) {
              return new ValidationError("Not all members support required group context extensions")
            }

            if (newGroupContextExtensions.newRequiredCapabilities !== undefined) {
              //2.2 new requiredCapabilities need to be supported by all existing (non removed/replaced) members
              if (!capabiltiesAreSupported(newGroupContextExtensions.newRequiredCapabilities, node.leaf.capabilities)) {
                return new ValidationError("Not all members support required capabilities")
              }
            }
          }
        }

        const keyPackageMatch = proposals.adds.some((kp) =>
          config.compareKeyPackageToLeafNode(kp.keyPackage, node.leaf),
        )
        if (keyPackageMatch) {
          return new ValidationError("Commit cannot contain an Add proposal for someone already in the group")
        }

        const leaf = leafChange !== undefined ? leafChange.newLeafNode : node.leaf

        existingCredentialTypes.add(leaf.credential.credentialType)
      }
    } else if (node?.nodeType === nodeTypes.parent) {
      const hpkeKey = bytesToBase64(node.parent.hpkePublicKey)
      if (input.hpkeKeys.has(hpkeKey)) return new ValidationError("hpke keys not unique")
    }
  }

  for (const add of proposals.adds) {
    //1.1.1 check that the leafNodes in add Proposals support proposedCredentialTypes
    if (!isSubset(existingCredentialTypes, add.keyPackage.leafNode.capabilities.credentials)) {
      throw new ValidationError("Proposals include leafNode that doesn't support a proposed leafNode's credentialType")
    }
  }

  for (const update of proposals.leafChanges.values()) {
    //1.1.2 new/updated credentialTypes need to be supported by all existing (non removed/replaced)  members
    if (!isSubset(existingCredentialTypes, update.newLeafNode.capabilities.credentials)) {
      throw new ValidationError("Proposals include leafNode that doesn't support a proposed leafNode's credentialType")
    }
  }
}

export function authenticateCredentials(authInput: CredentialBatchItem[][], authService: AuthenticationService) {
  return authService.validateCredentialBatch(authInput)
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
