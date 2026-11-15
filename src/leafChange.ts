import { LeafNode, LeafNodeUpdate, LeafNodeCommit } from "./leafNode.js"

export type LeafChange = {
  oldLeafNode: LeafNode | undefined
  newLeafNode: LeafNodeUpdate | LeafNodeCommit
  authenticated: boolean
}
