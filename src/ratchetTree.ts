import { Encoder, contramapEncoder, contramapEncoders } from "./codec/tlsEncoder"
import { Decoder, flatMapDecoder, mapDecoder } from "./codec/tlsDecoder"

import { decodeVarLenType, encodeVarLenType } from "./codec/variableLength"
import { decodeNodeType, encodeNodeType } from "./nodeType"
import { decodeOptional, encodeOptional } from "./codec/optional"
import { ParentNode, encodeParentNode, decodeParentNode } from "./parentNode"
import {
  copath,
  directPath,
  isLeaf,
  leafToNodeIndex,
  leafWidth,
  left,
  nodeToLeafIndex,
  parent,
  right,
  root,
} from "./treemath"
import { LeafNode, encodeLeafNode, decodeLeafNode } from "./leafNode"
import { constantTimeEqual } from "./util/constantTimeCompare"
import { InternalError, ValidationError } from "./mlsError"

export type Node = NodeParent | NodeLeaf
type NodeParent = { nodeType: "parent"; parent: ParentNode }
type NodeLeaf = { nodeType: "leaf"; leaf: LeafNode }

export const encodeNode: Encoder<Node> = (node) => {
  switch (node.nodeType) {
    case "parent":
      return contramapEncoders(
        [encodeNodeType, encodeParentNode],
        (n: NodeParent) => [n.nodeType, n.parent] as const,
      )(node)
    case "leaf":
      return contramapEncoders([encodeNodeType, encodeLeafNode], (n: NodeLeaf) => [n.nodeType, n.leaf] as const)(node)
  }
}

export const decodeNode: Decoder<Node> = flatMapDecoder(decodeNodeType, (nodeType): Decoder<Node> => {
  switch (nodeType) {
    case "parent":
      return mapDecoder(decodeParentNode, (parent) => ({
        nodeType,
        parent,
      }))
    case "leaf":
      return mapDecoder(decodeLeafNode, (leaf) => ({
        nodeType,
        leaf,
      }))
  }
})

export function getHpkePublicKey(n: Node): Uint8Array {
  switch (n.nodeType) {
    case "parent":
      return n.parent.hpkePublicKey
    case "leaf":
      return n.leaf.hpkePublicKey
  }
}

export type RatchetTree = (Node | undefined)[]

export function extendRatchetTree(tree: RatchetTree): RatchetTree {
  const lastIndex = tree.length - 1

  if (tree[lastIndex] === undefined) {
    throw new InternalError("The last node in the ratchet tree must be non-blank.")
  }

  // Compute the smallest full binary tree size >= current length
  const neededSize = nextFullBinaryTreeSize(tree.length)

  // Fill with `undefined` until tree has the needed size
  const copy = tree.slice()
  while (copy.length < neededSize) {
    copy.push(undefined)
  }

  return copy
}

// Compute the smallest 2^(d + 1) - 1 >= n
function nextFullBinaryTreeSize(n: number): number {
  let d = 0
  while ((1 << (d + 1)) - 1 < n) {
    d++
  }
  return (1 << (d + 1)) - 1
}

export function stripToMinimalCompleteTree(tree: RatchetTree): RatchetTree {
  const lastNonBlankIndex = findLastNonBlankIndex(tree)

  // Find the smallest 2^(d+1)-1 that is >= lastNonBlankIndex + 1
  // Then subtract one power to go to the next smaller full tree size
  let fullSize = 1
  while (fullSize <= lastNonBlankIndex) {
    fullSize = 2 * fullSize + 1
  }

  // Go one step back to get the last complete tree size <= lastNonBlankIndex
  let trimmedSize = Math.floor((fullSize - 1) / 2)

  return tree.slice(0, trimmedSize + 1)
}

function findLastNonBlankIndex(tree: RatchetTree): number {
  for (let i = tree.length - 1; i >= 0; i--) {
    if (tree[i] !== undefined) return i
  }
  return 0
}

/**
 * If the tree has 2d leaves, then it has 2d+1 - 1 nodes.
 * The ratchet_tree vector logically has this number of entries, but the sender MUST NOT include blank nodes after the last non-blank node.
 * The receiver MUST check that the last node in ratchet_tree is non-blank, and then extend the tree to the right until it has a length of the form 2d+1 - 1, adding the minimum number of blank values possible.
 * (Obviously, this may be done "virtually", by synthesizing blank nodes when required, as opposed to actually changing the structure in memory.)
 */
export function stripBlankNodes(tree: RatchetTree): RatchetTree {
  let lastNonBlank = tree.length - 1
  while (lastNonBlank >= 0 && tree[lastNonBlank] === undefined) {
    lastNonBlank--
  }

  return tree.slice(0, lastNonBlank + 1)
}

export const encodeRatchetTree: Encoder<RatchetTree> = contramapEncoder(
  encodeVarLenType(encodeOptional(encodeNode)),
  stripBlankNodes,
)

export const decodeRatchetTree: Decoder<RatchetTree> = mapDecoder(
  decodeVarLenType(decodeOptional(decodeNode)),
  extendRatchetTree,
)

export function findBlankLeafNodeIndex(tree: RatchetTree): number | undefined {
  const nodeIndex = tree.findIndex((node, nodeIndex) => node === undefined && isLeaf(nodeIndex))
  if (nodeIndex < 0) return undefined
  else return nodeIndex
}

export function findBlankLeafNodeIndexOrExtend(tree: RatchetTree): number {
  const blankLeaf = findBlankLeafNodeIndex(tree)
  return blankLeaf === undefined ? tree.length + 1 : blankLeaf
}

export function extendTree(tree: RatchetTree, leafNode: LeafNode): [RatchetTree, number] {
  const newRoot = undefined
  const insertedNodeIndex = tree.length + 1
  const newTree: RatchetTree = [...tree, newRoot, { nodeType: "leaf", leaf: leafNode }, ...new Array(tree.length - 1)]
  return [newTree, insertedNodeIndex]
}

export function addLeafNode(tree: RatchetTree, leafNode: LeafNode): [RatchetTree, number] {
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
        nodeType: "parent",
        parent: { ...parentNode.parent, unmergedLeaves: [...parentNode.parent.unmergedLeaves, insertedLeafIndex] },
      }
      copy[nodeIndex] = updated
    }
  }

  copy[blankLeaf] = { nodeType: "leaf", leaf: leafNode }

  return [copy, blankLeaf]
}

export function updateLeafNode(tree: RatchetTree, leafNode: LeafNode, leafIndex: number): RatchetTree {
  const leafNodeIndex = leafToNodeIndex(leafIndex)
  const pathToBlank = directPath(leafNodeIndex, leafWidth(tree.length))

  const copy = tree.slice()

  for (const nodeIndex of pathToBlank) {
    const node = tree[nodeIndex]
    if (node !== undefined) {
      copy[nodeIndex] = undefined
    }
  }
  copy[leafNodeIndex] = { nodeType: "leaf", leaf: leafNode }

  return copy
}

export function removeLeafNode(tree: RatchetTree, removedLeafIndex: number) {
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

/**
 * When the right subtree of the tree no longer has any non-blank nodes, it can be safely removed
 */
function condenseRatchetTreeAfterRemove(tree: RatchetTree) {
  return extendRatchetTree(stripBlankNodes(tree))
}

export function resolution(tree: (Node | undefined)[], nodeIndex: number): number[] {
  const node = tree[nodeIndex]

  if (node === undefined) {
    if (isLeaf(nodeIndex)) {
      return []
    }

    const l = left(nodeIndex)
    const r = right(nodeIndex)
    const leftRes = resolution(tree, l)
    const rightRes = resolution(tree, r)
    return [...leftRes, ...rightRes]
  }

  if (isLeaf(nodeIndex)) {
    return [nodeIndex]
  }

  const unmerged = node.nodeType === "parent" ? node.parent.unmergedLeaves : []
  return [nodeIndex, ...unmerged.map(leafToNodeIndex)]
}

export function filteredDirectPath(leafIndex: number, tree: RatchetTree): number[] {
  const leafNodeIndex = leafToNodeIndex(leafIndex)
  const leafWidth = nodeToLeafIndex(tree.length)
  const cp = copath(leafNodeIndex, leafWidth)
  // the filtered direct path of a leaf node L is the node's direct path,
  // with any node removed whose child on the copath of L has an empty resolution
  return directPath(leafNodeIndex, leafWidth).filter((_nodeIndex, n) => resolution(tree, cp[n]!).length !== 0)
}

export function filteredDirectPathAndCopathResolution(
  leafIndex: number,
  tree: RatchetTree,
): { resolution: number[]; nodeIndex: number }[] {
  const leafNodeIndex = leafToNodeIndex(leafIndex)
  const leafWidth = nodeToLeafIndex(tree.length)
  const cp = copath(leafNodeIndex, leafWidth)

  // the filtered direct path of a leaf node L is the node's direct path,
  // with any node removed whose child on the copath of L has an empty resolution
  return directPath(leafNodeIndex, leafWidth).reduce(
    (acc, cur, n) => {
      const r = resolution(tree, cp[n]!)
      if (r.length === 0) return acc
      else return [...acc, { nodeIndex: cur, resolution: r }]
    },
    [] as { resolution: number[]; nodeIndex: number }[],
  )
}

export function removeLeaves(tree: RatchetTree, leafIndices: number[]) {
  const copy = tree.slice()
  function shouldBeRemoved(leafIndex: number): boolean {
    return leafIndices.find((x) => leafIndex === x) !== undefined
  }
  for (const [i, n] of tree.entries()) {
    if (n !== undefined) {
      if (isLeaf(i) && shouldBeRemoved(nodeToLeafIndex(i))) {
        copy[i] = undefined
      } else if (n.nodeType === "parent") {
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
  leafIndex: number,
  f: (nodeIndex: number, node: ParentNode) => T | undefined,
): [T, number] | undefined {
  const rootIndex = root(leafWidth(tree.length))
  let currentIndex = leafToNodeIndex(leafIndex)
  while (currentIndex != rootIndex) {
    currentIndex = parent(currentIndex, leafWidth(tree.length))
    const currentNode = tree[currentIndex]
    if (currentNode !== undefined) {
      if (currentNode.nodeType === "leaf") {
        throw new InternalError("Expected parent node")
      }

      const result = f(currentIndex, currentNode.parent)
      if (result !== undefined) {
        return [result, currentIndex]
      }
    }
  }
}
export function findFirstNonBlankAncestor(tree: RatchetTree, nodeIndex: number): number {
  return (
    traverseToRoot(tree, nodeToLeafIndex(nodeIndex), (nodeIndex: number, _node: ParentNode) => nodeIndex)?.[0] ??
    root(leafWidth(tree.length))
  )
}

export function findLeafIndex(tree: RatchetTree, leaf: LeafNode): number | undefined {
  const foundIndex = tree.findIndex((node, nodeIndex) => {
    if (isLeaf(nodeIndex) && node !== undefined) {
      if (node.nodeType === "parent") throw new InternalError("Found parent node in leaf node position")
      //todo is there a better comparison method?
      return constantTimeEqual(encodeLeafNode(node.leaf), encodeLeafNode(leaf))
    }

    return false
  })

  return foundIndex === -1 ? undefined : nodeToLeafIndex(foundIndex)
}

export function getCredentialFromLeafIndex(ratchetTree: RatchetTree, leafIndex: number) {
  const senderLeafNode = ratchetTree[leafToNodeIndex(leafIndex)]

  if (senderLeafNode === undefined || senderLeafNode.nodeType === "parent")
    throw new ValidationError("Unable to find leafnode for leafIndex")
  return senderLeafNode.leaf.credential
}

export function getSignaturePublicKeyFromLeafIndex(ratchetTree: RatchetTree, leafIndex: number): Uint8Array {
  const leafNode = ratchetTree[leafToNodeIndex(leafIndex)]

  if (leafNode === undefined || leafNode.nodeType === "parent")
    throw new ValidationError("Unable to find leafnode for leafIndex")
  return leafNode.leaf.signaturePublicKey
}

export function getHpkePublicKeyFromNode(ratchetTree: RatchetTree, nodeIndex: number) {
  const node = ratchetTree[nodeIndex]

  if (node === undefined) throw new ValidationError("Unable to find node for nodeIndex")
  return getHpkePublicKey(node)
}
