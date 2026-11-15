import { GroupContext } from "./groupContext.js"
import {
  LeafNode,
  LeafNodeCommit,
  LeafNodeKeyPackage,
  LeafNodeUpdate,
  verifyLeafNodeSignature,
  verifyLeafNodeSignatureKeyPackage,
} from "./leafNode.js"
import { RequiredCapabilities } from "./requiredCapabilities.js"
import { CryptoVerificationError, MlsError, ValidationError } from "./mlsError.js"
import { Capabilities } from "./capabilities.js"
import { extensionsSupportedByCapabilities } from "./extension.js"
import { Signature } from "./crypto/signature.js"
import { LifetimeConfig } from "./lifetimeConfig.js"
import { KeyPackage, verifyKeyPackage } from "./keyPackage.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"

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
  groupContext: GroupContext,
  s: Signature,
): Promise<MlsError | undefined> {
  const signatureValid = await verifyLeafNodeSignature(leafNode, groupContext.groupId, leafIndex, s)

  if (!signatureValid) return new CryptoVerificationError("Could not verify leaf node signature")

  const commonError = await validateLeafNodeCommon(leafNode, requiredCapabilities)

  if (commonError !== undefined) return commonError
}

async function validateLeafNodeCommon(leafNode: LeafNode, requiredCapabilities: RequiredCapabilities | undefined) {
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
  s: Signature,
): Promise<MlsError | undefined> {
  const signatureValid = await verifyLeafNodeSignatureKeyPackage(leafNode, s)
  if (!signatureValid) return new CryptoVerificationError("Could not verify leaf node signature")

  //verify lifetime
  if (sentByClient || config.validateLifetimeOnReceive) {
    const currentTime = BigInt(Math.floor(Date.now() / 1000))
    if (leafNode.lifetime.notBefore > currentTime || leafNode.lifetime.notAfter < currentTime)
      return new ValidationError("Current time not within Lifetime")
  }

  const commonError = await validateLeafNodeCommon(leafNode, requiredCapabilities)

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
  s: Signature,
): Promise<MlsError | undefined> {
  if (kp.cipherSuite !== groupContext.cipherSuite) return new ValidationError("Invalid CipherSuite")

  if (kp.version !== groupContext.version) return new ValidationError("Invalid mls version")

  const leafNodeError = await validateLeafNodeKeyPackage(kp.leafNode, requiredCapabilities, sentByClient, config, s)
  if (leafNodeError !== undefined) return leafNodeError

  const signatureValid = await verifyKeyPackage(kp, s)
  if (!signatureValid) return new CryptoVerificationError("Invalid keypackage signature")

  if (constantTimeEqual(kp.initKey, kp.leafNode.hpkePublicKey))
    return new ValidationError("Cannot have identicial init and encryption keys")
}

export function capabiltiesAreSupported(caps: RequiredCapabilities, cs: Capabilities): boolean {
  return (
    caps.credentialTypes.every((c) => cs.credentials.includes(c)) &&
    caps.extensionTypes.every((e) => cs.extensions.includes(e)) &&
    caps.proposalTypes.every((p) => cs.proposals.includes(p))
  )
}

// function validateLeafNodeLifeTime(leafNode: LeafNodeKeyPackage) {
//   const currentTime = BigInt(Math.floor(Date.now() / 1000))
//   if (leafNode.lifetime.notBefore > currentTime || leafNode.lifetime.notAfter < currentTime)
//     return new ValidationError("Current time not within Lifetime")
// }
