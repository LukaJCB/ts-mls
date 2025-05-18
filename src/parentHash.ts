import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { Hash } from "./crypto/hash"
import { findFirstNonBlankAncestor, Node, RatchetTree, removeLeaves } from "./ratchetTree"
import { treeHash } from "./treeHash"
import { isLeaf, leafToNodeIndex, leafWidth, left, right, root } from "./treemath"

import { constantTimeEqual } from "./util/constantTimeCompare"

export type ParentHashInput = Readonly<{
  encryptionKey: Uint8Array
  parentHash: Uint8Array
  originalSiblingTreeHash: Uint8Array
}>

export const encodeParentHashInput: Encoder<ParentHashInput> = contramapEncoders(
  [encodeVarLenData, encodeVarLenData, encodeVarLenData],
  (i) => [i.encryptionKey, i.parentHash, i.originalSiblingTreeHash] as const,
)

export const decodeParentHashInput: Decoder<ParentHashInput> = mapDecoders(
  [decodeVarLenData, decodeVarLenData, decodeVarLenData],
  (encryptionKey, parentHash, originalSiblingTreeHash) => ({
    encryptionKey,
    parentHash,
    originalSiblingTreeHash,
  }),
)

function validateParentHashCoverage(parentIndices: number[], coverage: Record<number, number>): boolean {
  for (const index of parentIndices) {
    if ((coverage[index] ?? 0) !== 1) {
      return false
    }
  }
  return true
}

export async function verifyParentHashes(tree: RatchetTree, h: Hash) {
  const parentNodes = tree.reduce<number[]>((acc, cur, index) => {
    if (cur !== undefined && cur.nodeType === "parent") {
      return [...acc, index]
    } else return acc
  }, [])

  const coverage = await parentHashCoverage(tree, h)

  return validateParentHashCoverage(parentNodes, coverage)
}

/**
 * Traverse tree from bottom up, verifying that all non-blank parent nodes are covered by exactly one chain
 */
function parentHashCoverage(tree: RatchetTree, h: Hash): Promise<Record<number, number>> {
  const leaves = tree.filter((_v, i) => isLeaf(i))
  return leaves.reduce(
    async (acc, leafNode, leafIndex) => {
      if (leafNode === undefined) return acc

      let currentIndex = leafToNodeIndex(leafIndex)
      let updated = { ...(await acc) }

      const rootIndex = root(leafWidth(tree.length))

      while (currentIndex !== rootIndex) {
        const currentNode = tree[currentIndex]

        // skip blank nodes
        if (currentNode === undefined) {
          continue
        }

        // parentHashNodeIndex is the node index where the nearest non blank ancestor was
        const [parentHash, parentHashNodeIndex] = await calculateParentHash(tree, currentIndex, h)

        if (parentHashNodeIndex === undefined) {
          throw new Error("Internal error: Reached root? todo")
        }

        const expectedParentHash = getParentHash(currentNode)

        if (expectedParentHash !== undefined && constantTimeEqual(parentHash, expectedParentHash)) {
          const newCount = (updated[parentHashNodeIndex] ?? 0) + 1
          updated = { ...updated, [parentHashNodeIndex]: newCount }
        } else {
          // skip to next leaf
          break
        }

        currentIndex = parentHashNodeIndex
      }

      return updated
    },
    Promise.resolve({} as Record<number, number>),
  )
}

function getParentHash(node: Node): Uint8Array | undefined {
  if (node.nodeType === "parent") return node.parent.parentHash
  else if (node.leaf.leafNodeSource === "commit") return node.leaf.parentHash
}

/**
 * Calculcates parent hash for a given node or leaf and returns the node index of the parent or undefined if the given node is the root node.
 */
export async function calculateParentHash(
  tree: RatchetTree,
  nodeIndex: number,
  h: Hash,
): Promise<[Uint8Array, number | undefined]> {
  if (nodeIndex === root(leafWidth(tree.length))) {
    return [new Uint8Array(), undefined]
  }

  const parentNodeIndex = findFirstNonBlankAncestor(tree, nodeIndex)

  const siblingIndex = nodeIndex < parentNodeIndex ? right(parentNodeIndex) : left(parentNodeIndex)

  const parentNode = tree[parentNodeIndex]

  if (parentNode === undefined || parentNode.nodeType === "leaf") throw new Error("Expected non-blank parent Noded")

  const removedUnmerged = removeLeaves(tree, parentNode.parent.unmergedLeaves)

  const originalSiblingTreeHash = await treeHash(removedUnmerged, siblingIndex, h)

  const input = {
    encryptionKey: parentNode.parent.hpkePublicKey,
    parentHash: parentNode.parent.parentHash,
    originalSiblingTreeHash,
  }

  return [await h.digest(encodeParentHashInput(input)), parentNodeIndex]
}
