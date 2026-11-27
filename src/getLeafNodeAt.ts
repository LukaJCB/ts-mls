import { LeafNode } from "./leafNode.js"
import { UsageError, InternalError } from "./mlsError.js"
import { nodeTypes } from "./nodeType.js"
import { RatchetTree } from "./ratchetTree.js"
import { LeafIndex, leafToNodeIndex, toLeafIndex } from "./treemath.js"

export function getLeafNode(tree: RatchetTree, leafIndex: LeafIndex): LeafNode {
  const idx = leafToNodeIndex(toLeafIndex(leafIndex))
  const leaf = tree[idx]
  if (!leaf) throw new UsageError("No leaf at given leafIndex")
  if (leaf.nodeType !== nodeTypes.leaf) throw new InternalError("Expected leaf node")
  return leaf.leaf
}
