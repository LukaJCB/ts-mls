import { KeyPackage } from "./keyPackage"
import { LeafNode } from "./leafNode"
import { constantTimeEqual } from "./util/constantTimeCompare"

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
