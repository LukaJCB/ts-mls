import { encodeUint32, decodeUint32 } from "./codec/number"
import { encodeOptional, decodeOptional } from "./codec/optional"
import { Decoder, mapDecoders, flatMapDecoder } from "./codec/tlsDecoder"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder"
import { encodeVarLenData, decodeVarLenData } from "./codec/variableLength"
import { Hash } from "./crypto/hash"
import { LeafNode, encodeLeafNode, decodeLeafNode } from "./leafNode"
import { InternalError } from "./mlsError"
import { encodeNodeType, decodeNodeType } from "./nodeType"
import { ParentNode, encodeParentNode, decodeParentNode } from "./parentNode"
import { RatchetTree } from "./ratchetTree"
import { rootFromNodeWidth, isLeaf, nodeToLeafIndex, left, right, NodeIndex } from "./treemath"

export type TreeHashInput = LeafNodeHashInput | ParentNodeHashInput
type LeafNodeHashInput = {
  nodeType: "leaf"
  leafIndex: number
  leafNode: LeafNode | undefined
}
type ParentNodeHashInput = {
  nodeType: "parent"
  parentNode: ParentNode | undefined
  leftHash: Uint8Array
  rightHash: Uint8Array
}

export const encodeLeafNodeHashInput: Encoder<LeafNodeHashInput> = contramapEncoders(
  [encodeNodeType, encodeUint32, encodeOptional(encodeLeafNode)],
  (input) => [input.nodeType, input.leafIndex, input.leafNode] as const,
)

export const decodeLeafNodeHashInput: Decoder<LeafNodeHashInput> = mapDecoders(
  [decodeUint32, decodeOptional(decodeLeafNode)],
  (leafIndex, leafNode) => ({
    nodeType: "leaf",
    leafIndex,
    leafNode,
  }),
)

export const encodeParentNodeHashInput: Encoder<ParentNodeHashInput> = contramapEncoders(
  [encodeNodeType, encodeOptional(encodeParentNode), encodeVarLenData, encodeVarLenData],
  (input) => [input.nodeType, input.parentNode, input.leftHash, input.rightHash] as const,
)

export const decodeParentNodeHashInput: Decoder<ParentNodeHashInput> = mapDecoders(
  [decodeOptional(decodeParentNode), decodeVarLenData, decodeVarLenData],
  (parentNode, leftHash, rightHash) => ({
    nodeType: "parent",
    parentNode,
    leftHash,
    rightHash,
  }),
)

export const encodeTreeHashInput: Encoder<TreeHashInput> = (input) => {
  switch (input.nodeType) {
    case "leaf":
      return encodeLeafNodeHashInput(input)
    case "parent":
      return encodeParentNodeHashInput(input)
  }
}
export const decodeTreeHashInput: Decoder<TreeHashInput> = flatMapDecoder(
  decodeNodeType,
  (nodeType): Decoder<TreeHashInput> => {
    switch (nodeType) {
      case "leaf":
        return decodeLeafNodeHashInput
      case "parent":
        return decodeParentNodeHashInput
    }
  },
)

export async function treeHashRoot(tree: RatchetTree, h: Hash): Promise<Uint8Array> {
  return treeHash(tree, rootFromNodeWidth(tree.length), h)
}

export async function treeHash(tree: RatchetTree, subtreeIndex: NodeIndex, h: Hash): Promise<Uint8Array> {
  if (isLeaf(subtreeIndex)) {
    const leafNode = tree[subtreeIndex]
    if (leafNode?.nodeType === "parent") throw new InternalError("Somehow found parent node in leaf position")
    const input = encodeLeafNodeHashInput({
      nodeType: "leaf",
      leafIndex: nodeToLeafIndex(subtreeIndex),
      leafNode: leafNode?.leaf,
    })
    return await h.digest(input)
  } else {
    const parentNode = tree[subtreeIndex]
    if (parentNode?.nodeType === "leaf") throw new InternalError("Somehow found leaf node in parent position")
    const leftHash = await treeHash(tree, left(subtreeIndex), h)
    const rightHash = await treeHash(tree, right(subtreeIndex), h)
    const input = {
      nodeType: "parent",
      parentNode: parentNode?.parent,
      leftHash: leftHash,
      rightHash: rightHash,
    } as const

    return await h.digest(encodeParentNodeHashInput(input))
  }
}
