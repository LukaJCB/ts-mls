import { Encoder, contramapBufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { Decoder, flatMapDecoder, mapDecoder } from "./codec/tlsDecoder.js"

import { varLenTypeDecoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { nodeTypeDecoder, nodeTypeEncoder, nodeTypes } from "./nodeType.js"
import { optionalDecoder, optionalEncoder } from "./codec/optional.js"
import { ParentNode, parentNodeEncoder, parentNodeDecoder } from "./parentNode.js"
import {
  copath,
  directPath,
  isLeaf,
  LeafIndex,
  leafToNodeIndex,
  leafWidth,
  left,
  NodeIndex,
  nodeToLeafIndex,
  parent,
  right,
  root,
  toLeafIndex,
  toNodeIndex,
} from "./treemath.js"
import { LeafNode, leafNodeEncoder, leafNodeDecoder, leafNodeEqual } from "./leafNode.js"
import { InternalError, ValidationError } from "./mlsError.js"

/** @public */
export type Node = NodeParent | NodeLeaf

/** @public */
export type NodeParent = { nodeType: typeof nodeTypes.parent; parent: ParentNode }

/** @public */
export type NodeLeaf = { nodeType: typeof nodeTypes.leaf; leaf: LeafNode }

export const nodeEncoder: Encoder<Node> = (node) => {
  switch (node.nodeType) {
    case nodeTypes.parent:
      return contramapBufferEncoders(
        [nodeTypeEncoder, parentNodeEncoder],
        (n: NodeParent) => [n.nodeType, n.parent] as const,
      )(node)
    case nodeTypes.leaf:
      return contramapBufferEncoders(
        [nodeTypeEncoder, leafNodeEncoder],
        (n: NodeLeaf) => [n.nodeType, n.leaf] as const,
      )(node)
  }
}

export const nodeDecoder: Decoder<Node> = flatMapDecoder(nodeTypeDecoder, (nodeType): Decoder<Node> => {
  switch (nodeType) {
    case nodeTypes.parent:
      return mapDecoder(parentNodeDecoder, (parent) => ({
        nodeType,
        parent,
      }))
    case nodeTypes.leaf:
      return mapDecoder(leafNodeDecoder, (leaf) => ({
        nodeType,
        leaf,
      }))
  }
})

export function getHpkePublicKey(n: Node): Uint8Array {
  switch (n.nodeType) {
    case nodeTypes.parent:
      return n.parent.hpkePublicKey
    case nodeTypes.leaf:
      return n.leaf.hpkePublicKey
  }
}

/** @public */
export type RatchetTree = (Node | undefined)[]

function extendRatchetTree(tree: RatchetTree): RatchetTree {
  const lastIndex = tree.length - 1

  if (tree[lastIndex] === undefined) {
    throw new InternalError("The last node in the ratchet tree must be non-blank.")
  }

  // Compute the smallest full binary tree size >= current length
  const neededSize = nextFullBinaryTreeSize(tree.length)

  // Fill with `undefined` until tree has the needed size
  while (tree.length < neededSize) {
    tree.push(undefined)
  }

  return tree
}

// Compute the smallest 2^(d + 1) - 1 >= n
function nextFullBinaryTreeSize(n: number): number {
  const value = n + 1
  const exponent = 32 - Math.clz32(value - 1)
  return 2 ** exponent - 1
}

/**
 * If the tree has 2d leaves, then it has 2d+1 - 1 nodes.
 * The ratchet_tree vector logically has this number of entries, but the sender MUST NOT include blank nodes after the last non-blank node.
 * The receiver MUST check that the last node in ratchet_tree is non-blank, and then extend the tree to the right until it has a length of the form 2d+1 - 1, adding the minimum number of blank values possible.
 * (Obviously, this may be done "virtually", by synthesizing blank nodes when required, as opposed to actually changing the structure in memory.)
 */
function stripBlankNodes(tree: RatchetTree): RatchetTree {
  let lastNonBlank = tree.length - 1

  while (lastNonBlank >= 0 && tree[lastNonBlank] === undefined) {
    lastNonBlank--
  }

  if (lastNonBlank === tree.length - 1) {
    return tree
  }

  return tree.splice(0, lastNonBlank + 1)
}

export const ratchetTreeEncoder: Encoder<RatchetTree> = contramapBufferEncoder(
  varLenTypeEncoder(optionalEncoder(nodeEncoder)),
  stripBlankNodes,
)

export const ratchetTreeDecoder: Decoder<RatchetTree> = mapDecoder(
  varLenTypeDecoder(optionalDecoder(nodeDecoder)),
  extendRatchetTree,
)

export function findBlankLeafNodeIndex(tree: RatchetTree): NodeIndex | undefined {
  const nodeIndex = tree.findIndex((node, nodeIndex) => node === undefined && isLeaf(toNodeIndex(nodeIndex)))
  if (nodeIndex < 0) return undefined
  else return toNodeIndex(nodeIndex)
}

export function findBlankLeafNodeIndexOrExtend(tree: RatchetTree): NodeIndex {
  const blankLeaf = findBlankLeafNodeIndex(tree)
  return blankLeaf === undefined ? toNodeIndex(tree.length + 1) : blankLeaf
}

export function extendTree(tree: RatchetTree, leafNode: LeafNode): [RatchetTree, NodeIndex] {
  const newRoot = undefined
  const insertedNodeIndex = toNodeIndex(tree.length + 1)
  const newTree: RatchetTree = [
    ...tree,
    newRoot,
    { nodeType: nodeTypes.leaf, leaf: leafNode },
    ...new Array<Node | undefined>(tree.length - 1),
  ]
  return [newTree, insertedNodeIndex]
}

export function extendTreeMutable(mutableTree: RatchetTree, leafNode: LeafNode): NodeIndex {
  const newRoot = undefined
  const insertedNodeIndex = toNodeIndex(mutableTree.length + 1)
  const originalLength = mutableTree.length
  mutableTree.push(newRoot);
  mutableTree.push({ nodeType: nodeTypes.leaf, leaf: leafNode });


  for (let i = 0; i < originalLength - 1; i++) {
    mutableTree.push(undefined);
  }
  return insertedNodeIndex
}

export function addLeafNode(tree: RatchetTree, leafNode: LeafNode): [RatchetTree, NodeIndex] {
  const blankLeaf = findBlankLeafNodeIndex(tree)
  if (blankLeaf === undefined) {
    return extendTree(tree, leafNode)
  }

  const insertedLeafIndex = nodeToLeafIndex(blankLeaf)
  const dp = directPath(blankLeaf, leafWidth(tree.length))

  const copy = tree.slice()

  for (const nodeIndex of dp) {
    const node = tree[nodeIndex]
    if (node !== undefined) {
      const parentNode = node as NodeParent

      const updated: NodeParent = {
        nodeType: nodeTypes.parent,
        parent: { ...parentNode.parent, unmergedLeaves: [...parentNode.parent.unmergedLeaves, insertedLeafIndex] },
      }
      copy[nodeIndex] = updated
    }
  }

  copy[blankLeaf] = { nodeType: nodeTypes.leaf, leaf: leafNode }

  return [copy, blankLeaf]
}

export function addLeafNodeMutable(mutableTree: RatchetTree, leafNode: LeafNode): NodeIndex {
  const blankLeaf = findBlankLeafNodeIndex(mutableTree)
  if (blankLeaf === undefined) {
    return extendTreeMutable(mutableTree, leafNode)
  }

  const insertedLeafIndex = nodeToLeafIndex(blankLeaf)
  const dp = directPath(blankLeaf, leafWidth(mutableTree.length))


  for (const nodeIndex of dp) {
    const node = mutableTree[nodeIndex]
    if (node !== undefined) {
      const parentNode = node as NodeParent

      const updated: NodeParent = {
        nodeType: nodeTypes.parent,
        parent: { ...parentNode.parent, unmergedLeaves: [...parentNode.parent.unmergedLeaves, insertedLeafIndex] },
      }
      mutableTree[nodeIndex] = updated
    }
  }

  mutableTree[blankLeaf] = { nodeType: nodeTypes.leaf, leaf: leafNode }

  return blankLeaf
}

export function updateLeafNode(tree: RatchetTree, leafNode: LeafNode, leafIndex: LeafIndex): RatchetTree {
  const leafNodeIndex = leafToNodeIndex(leafIndex)
  const pathToBlank = directPath(leafNodeIndex, leafWidth(tree.length))

  const copy = tree.slice()

  for (const nodeIndex of pathToBlank) {
    const node = tree[nodeIndex]
    if (node !== undefined) {
      copy[nodeIndex] = undefined
    }
  }
  copy[leafNodeIndex] = { nodeType: nodeTypes.leaf, leaf: leafNode }

  return copy
}


export function updateLeafNodeMutable(mutableTree: RatchetTree, leafNode: LeafNode, leafIndex: LeafIndex): void {
  const leafNodeIndex = leafToNodeIndex(leafIndex)
  const pathToBlank = directPath(leafNodeIndex, leafWidth(mutableTree.length))

  for (const nodeIndex of pathToBlank) {
    const node = mutableTree[nodeIndex]
    if (node !== undefined) {
      mutableTree[nodeIndex] = undefined
    }
  }
  mutableTree[leafNodeIndex] = { nodeType: nodeTypes.leaf, leaf: leafNode }
}

export function removeLeafNode(tree: RatchetTree, removedLeafIndex: LeafIndex) {
  const leafNodeIndex = leafToNodeIndex(removedLeafIndex)
  const pathToBlank = directPath(leafNodeIndex, leafWidth(tree.length))

  const copy = tree.slice()

  for (const nodeIndex of pathToBlank) {
    const node = tree[nodeIndex]
    if (node !== undefined) {
      copy[nodeIndex] = undefined
    }
  }
  copy[leafNodeIndex] = undefined

  return condenseRatchetTreeAfterRemove(copy)
}


export function removeLeafNodeMutable(mutableTree: RatchetTree, removedLeafIndex: LeafIndex): void {
  const leafNodeIndex = leafToNodeIndex(removedLeafIndex)
  const pathToBlank = directPath(leafNodeIndex, leafWidth(mutableTree.length))


  for (const nodeIndex of pathToBlank) {
    const node = mutableTree[nodeIndex]
    if (node !== undefined) {
      mutableTree[nodeIndex] = undefined
    }
  }
  mutableTree[leafNodeIndex] = undefined

  condenseRatchetTreeAfterRemove(mutableTree)
}

/**
 * When the right subtree of the tree no longer has any non-blank nodes, it can be safely removed
 */
function condenseRatchetTreeAfterRemove(tree: RatchetTree) {
  return extendRatchetTree(stripBlankNodes(tree))
}

export function resolution(tree: (Node | undefined)[], nodeIndex: NodeIndex): NodeIndex[] {
  const node = tree[nodeIndex]

  if (node === undefined) {
    if (isLeaf(nodeIndex)) {
      return []
    }

    const l = left(nodeIndex)
    const r = right(nodeIndex)
    const leftRes = resolution(tree, l)
    const rightRes = resolution(tree, r)

    if (leftRes.length === 0) return rightRes
    if (rightRes.length === 0) return leftRes

    leftRes.push(...rightRes)
    return leftRes
  }

  if (isLeaf(nodeIndex)) {
    return [nodeIndex]
  }

  const unmerged = node.nodeType === nodeTypes.parent ? node.parent.unmergedLeaves : []
  return [nodeIndex, ...unmerged.map((u) => leafToNodeIndex(toLeafIndex(u)))]
}

export function filteredDirectPath(leafIndex: LeafIndex, tree: RatchetTree): NodeIndex[] {
  const leafNodeIndex = leafToNodeIndex(leafIndex)
  const leafWidth = nodeToLeafIndex(toNodeIndex(tree.length))
  const cp = copath(leafNodeIndex, leafWidth)
  // the filtered direct path of a leaf node L is the node's direct path,
  // with any node removed whose child on the copath of L has an empty resolution
  return directPath(leafNodeIndex, leafWidth).filter((_nodeIndex, n) => resolution(tree, cp[n]!).length !== 0)
}

export function filteredDirectPathAndCopathResolution(
  leafIndex: LeafIndex,
  tree: RatchetTree,
): { resolution: NodeIndex[]; nodeIndex: NodeIndex }[] {
  const leafNodeIndex = leafToNodeIndex(leafIndex)
  const lWidth = leafWidth(tree.length)
  const cp = copath(leafNodeIndex, lWidth)

  // the filtered direct path of a leaf node L is the node's direct path,
  // with any node removed whose child on the copath of L has an empty resolution
  const result: { resolution: NodeIndex[]; nodeIndex: NodeIndex }[] = []
  const direct = directPath(leafNodeIndex, lWidth)

  for (let n = 0; n < direct.length; n++) {
    const cur = direct[n]!
    const r = resolution(tree, cp[n]!)
    if (r.length !== 0) {
      result.push({ nodeIndex: cur, resolution: r })
    }
  }

  return result
}

export function removeLeaves(tree: RatchetTree, leafIndices: LeafIndex[]) {
  const copy = tree.slice()
  const removedLeaves = new Set(leafIndices)

  function shouldBeRemoved(leafIndex: number): boolean {
    return removedLeaves.has(toLeafIndex(leafIndex))
  }
  for (const [i, n] of tree.entries()) {
    if (n !== undefined) {
      const nodeIndex = toNodeIndex(i)
      if (isLeaf(nodeIndex) && shouldBeRemoved(nodeToLeafIndex(nodeIndex))) {
        copy[i] = undefined
      } else if (n.nodeType === nodeTypes.parent) {
        copy[i] = {
          ...n,
          parent: { ...n.parent, unmergedLeaves: n.parent.unmergedLeaves.filter((l) => !shouldBeRemoved(l)) },
        }
      }
    }
  }
  return condenseRatchetTreeAfterRemove(copy)
}

export function traverseToRoot<T>(
  tree: RatchetTree,
  leafIndex: LeafIndex,
  f: (nodeIndex: NodeIndex, node: ParentNode) => T | undefined,
): [T, NodeIndex] | undefined {
  const rootIndex = root(leafWidth(tree.length))
  let currentIndex = leafToNodeIndex(leafIndex)
  while (currentIndex != rootIndex) {
    currentIndex = parent(currentIndex, leafWidth(tree.length))
    const currentNode = tree[currentIndex]
    if (currentNode !== undefined) {
      if (currentNode.nodeType === nodeTypes.leaf) {
        throw new InternalError("Expected parent node")
      }

      const result = f(currentIndex, currentNode.parent)
      if (result !== undefined) {
        return [result, currentIndex]
      }
    }
  }
}
export function findFirstNonBlankAncestor(tree: RatchetTree, nodeIndex: NodeIndex): NodeIndex {
  return (
    traverseToRoot(tree, nodeToLeafIndex(nodeIndex), (nodeIndex: NodeIndex, _node: ParentNode) => nodeIndex)?.[0] ??
    root(leafWidth(tree.length))
  )
}

export function findLeafIndex(tree: RatchetTree, leaf: LeafNode): LeafIndex | undefined {
  const foundIndex = tree.findIndex((node, nodeIndex) => {
    if (isLeaf(toNodeIndex(nodeIndex)) && node !== undefined) {
      if (node.nodeType === nodeTypes.parent) throw new InternalError("Found parent node in leaf node position")
      return leafNodeEqual(leaf, node.leaf)
    }

    return false
  })

  return foundIndex === -1 ? undefined : nodeToLeafIndex(toNodeIndex(foundIndex))
}

export function getCredentialFromLeafIndex(ratchetTree: RatchetTree, leafIndex: LeafIndex) {
  const senderLeafNode = ratchetTree[leafToNodeIndex(leafIndex)]

  if (senderLeafNode === undefined || senderLeafNode.nodeType === nodeTypes.parent)
    throw new ValidationError("Unable to find leafnode for leafIndex")
  return senderLeafNode.leaf.credential
}

export function getSignaturePublicKeyFromLeafIndex(ratchetTree: RatchetTree, leafIndex: LeafIndex): Uint8Array {
  const leafNode = ratchetTree[leafToNodeIndex(leafIndex)]

  if (leafNode === undefined || leafNode.nodeType === nodeTypes.parent)
    throw new ValidationError("Unable to find leafnode for leafIndex")
  return leafNode.leaf.signaturePublicKey
}
