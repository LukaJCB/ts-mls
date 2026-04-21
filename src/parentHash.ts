import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder, encode } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { Hash } from "./crypto/hash.js"
import { InternalError } from "./mlsError.js"
import { findFirstNonBlankAncestor, Node, RatchetTree, removeLeaves } from "./ratchetTree.js"
import { treeHash } from "./treeHash.js"
import { isLeaf, LeafIndex, leafWidth, left, NodeIndex, right, root, toNodeIndex } from "./treemath.js"
import { nodeTypes } from "./nodeType.js"
import { leafNodeSources } from "./leafNodeSource.js"

import { constantTimeEqual } from "./util/constantTimeCompare.js"

interface ParentHashInput {
  encryptionKey: Uint8Array
  parentHash: Uint8Array
  originalSiblingTreeHash: Uint8Array
}

export const parentHashInputEncoder: Encoder<ParentHashInput> = contramapBufferEncoders(
  [varLenDataEncoder, varLenDataEncoder, varLenDataEncoder],
  (i) => [i.encryptionKey, i.parentHash, i.originalSiblingTreeHash] as const,
)

export const parentHashInputDecoder: Decoder<ParentHashInput> = mapDecoders(
  [varLenDataDecoder, varLenDataDecoder, varLenDataDecoder],
  (encryptionKey, parentHash, originalSiblingTreeHash) => ({
    encryptionKey,
    parentHash,
    originalSiblingTreeHash,
  }),
)

export async function verifyParentHashes(tree: RatchetTree, h: Hash): Promise<boolean> {
  let hasParent = false
  for (let i = 0; i < tree.length; i++) {
    const cur = tree[i]
    if (cur !== undefined && cur.nodeType === nodeTypes.parent) {
      hasParent = true
      break
    }
  }
  if (!hasParent) return true

  const coverage = await parentHashCoverage(tree, h)

  for (let i = 0; i < tree.length; i++) {
    const cur = tree[i]
    if (cur !== undefined && cur.nodeType === nodeTypes.parent) {
      if ((coverage.get(i) ?? 0) !== 1) return false
    }
  }
  return true
}

/**
 * Traverse tree from bottom up, verifying that all non-blank parent nodes are covered by exactly one chain.
 * Per-leaf walks run in parallel; calculateParentHash is memoized by nodeIndex since, for a fixed tree,
 * it is a pure function of nodeIndex.
 */
async function parentHashCoverage(tree: RatchetTree, h: Hash): Promise<Map<number, number>> {
  const rootIndex = root(leafWidth(tree.length))

  const memo = new Map<NodeIndex, Promise<[Uint8Array, NodeIndex | undefined]>>()
  const memoedCalculate = (idx: NodeIndex): Promise<[Uint8Array, NodeIndex | undefined]> => {
    let p = memo.get(idx)
    if (p === undefined) {
      p = calculateParentHash(tree, idx, h)
      memo.set(idx, p)
    }
    return p
  }

  const leafCovered = await Promise.all(
    tree.map(async (node, nodeIndex) => {
      const startIndex = toNodeIndex(nodeIndex)
      if (!isLeaf(startIndex) || node === undefined) return undefined

      const covered: NodeIndex[] = []
      let currentIndex: NodeIndex = startIndex
      let currentNode: Node | undefined = node

      while (currentIndex !== rootIndex) {
        const [parentHash, parentHashNodeIndex] = await memoedCalculate(currentIndex)

        if (parentHashNodeIndex === undefined) {
          throw new InternalError("Reached root before completing parent hash coeverage")
        }

        const expectedParentHash = getParentHash(currentNode)

        if (expectedParentHash !== undefined && constantTimeEqual(parentHash, expectedParentHash)) {
          covered.push(parentHashNodeIndex)
        } else {
          break
        }

        currentIndex = parentHashNodeIndex
        const nextNode = tree[currentIndex]
        if (nextNode === undefined) break
        currentNode = nextNode
      }

      return covered
    }),
  )

  const coverage = new Map<number, number>()
  for (const covered of leafCovered) {
    if (covered === undefined) continue
    for (const idx of covered) {
      coverage.set(idx, (coverage.get(idx) ?? 0) + 1)
    }
  }
  return coverage
}

function getParentHash(node: Node): Uint8Array | undefined {
  if (node.nodeType === nodeTypes.parent) return node.parent.parentHash
  else if (node.leaf.leafNodeSource === leafNodeSources.commit) return node.leaf.parentHash
}

/**
 * Calculcates parent hash for a given node or leaf and returns the node index of the parent or undefined if the given node is the root node.
 */
export async function calculateParentHash(
  tree: RatchetTree,
  nodeIndex: NodeIndex,
  h: Hash,
): Promise<[Uint8Array, NodeIndex | undefined]> {
  const rootIndex = root(leafWidth(tree.length))
  if (nodeIndex === rootIndex) {
    return [new Uint8Array(), undefined]
  }

  const parentNodeIndex = findFirstNonBlankAncestor(tree, nodeIndex)

  const parentNode = tree[parentNodeIndex]

  if (parentNodeIndex === rootIndex && parentNode === undefined) {
    return [new Uint8Array(), parentNodeIndex]
  }

  const siblingIndex = nodeIndex < parentNodeIndex ? right(parentNodeIndex) : left(parentNodeIndex)

  if (parentNode === undefined || parentNode.nodeType === nodeTypes.leaf)
    throw new InternalError("Expected non-blank parent Node")

  const removedUnmerged = removeLeaves(tree, parentNode.parent.unmergedLeaves as LeafIndex[])

  const originalSiblingTreeHash = await treeHash(removedUnmerged, siblingIndex, h)

  const input = {
    encryptionKey: parentNode.parent.hpkePublicKey,
    parentHash: parentNode.parent.parentHash,
    originalSiblingTreeHash,
  }

  return [await h.digest(encode(parentHashInputEncoder, input)), parentNodeIndex]
}
