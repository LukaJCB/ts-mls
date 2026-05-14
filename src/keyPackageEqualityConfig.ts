import { encode } from "./codec/tlsEncoder.js"
import { credentialEncoder } from "./credential.js"
import { KeyPackage } from "./keyPackage.js"
import { LeafNode } from "./leafNode.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"

/** @public */
export interface KeyPackageEqualityConfig {
  compareKeyPackages(a: KeyPackage, b: KeyPackage): boolean
  compareKeyPackageToLeafNode(a: KeyPackage, b: LeafNode): boolean
}

/** @public */
export const defaultKeyPackageEqualityConfig: KeyPackageEqualityConfig = {
  compareKeyPackages(a, b) {
    return constantTimeEqual(a.leafNode.signaturePublicKey, b.leafNode.signaturePublicKey)
  },
  compareKeyPackageToLeafNode(a, b) {
    if (constantTimeEqual(a.leafNode.signaturePublicKey, b.signaturePublicKey)) return true
    return constantTimeEqual(encode(credentialEncoder, a.leafNode.credential), encode(credentialEncoder, b.credential))
  },
}
