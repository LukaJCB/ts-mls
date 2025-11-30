import { KeyPackage } from "./keyPackage.js"
import { LeafNode } from "./leafNode.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"

export interface KeyPackageEqualityConfig {
  compareKeyPackages(a: KeyPackage, b: KeyPackage): boolean
  compareKeyPackageToLeafNode(a: KeyPackage, b: LeafNode): boolean
}

export const defaultKeyPackageEqualityConfig: KeyPackageEqualityConfig = {
  compareKeyPackages(a, b) {
    return constantTimeEqual(a.leafNode.signaturePublicKey, b.leafNode.signaturePublicKey)
  },
  compareKeyPackageToLeafNode(a, b) {
    return constantTimeEqual(a.leafNode.signaturePublicKey, b.signaturePublicKey)
  },
}
