import { uint32Encoder, decodeUint32 } from "./codec/number.js"
import { optionalEncoder, decodeOptional } from "./codec/optional.js"
import { Decoder, mapDecoders, flatMapDecoder } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders, encode } from "./codec/tlsEncoder.js"
import { varLenDataEncoder, decodeVarLenData } from "./codec/variableLength.js"
import { Hash } from "./crypto/hash.js"
import { LeafNode, leafNodeEncoder, decodeLeafNode } from "./leafNode.js"
import { InternalError } from "./mlsError.js"
import { decodeNodeType, nodeTypeEncoder, nodeTypes } from "./nodeType.js"
import { ParentNode, parentNodeEncoder, decodeParentNode } from "./parentNode.js"
import { RatchetTree } from "./ratchetTree.js"
import { rootFromNodeWidth, isLeaf, nodeToLeafIndex, left, right, NodeIndex } from "./treemath.js"

export type TreeHashInput = LeafNodeHashInput | ParentNodeHashInput
type LeafNodeHashInput = {
  nodeType: typeof nodeTypes.leaf
  leafIndex: number
  leafNode: LeafNode | undefined
}
type ParentNodeHashInput = {
  nodeType: typeof nodeTypes.parent
  parentNode: ParentNode | undefined
  leftHash: Uint8Array
  rightHash: Uint8Array
}

export const leafNodeHashInputEncoder: BufferEncoder<LeafNodeHashInput> = contramapBufferEncoders(
  [nodeTypeEncoder, uint32Encoder, optionalEncoder(leafNodeEncoder)],
  (input) => [input.nodeType, input.leafIndex, input.leafNode] as const,
)

export const decodeLeafNodeHashInput: Decoder<LeafNodeHashInput> = mapDecoders(
  [decodeUint32, decodeOptional(decodeLeafNode)],
  (leafIndex, leafNode) => ({
    nodeType: nodeTypes.leaf,
    leafIndex,
    leafNode,
  }),
)

export const parentNodeHashInputEncoder: BufferEncoder<ParentNodeHashInput> = contramapBufferEncoders(
  [nodeTypeEncoder, optionalEncoder(parentNodeEncoder), varLenDataEncoder, varLenDataEncoder],
  (input) => [input.nodeType, input.parentNode, input.leftHash, input.rightHash] as const,
)

export const decodeParentNodeHashInput: Decoder<ParentNodeHashInput> = mapDecoders(
  [decodeOptional(decodeParentNode), decodeVarLenData, decodeVarLenData],
  (parentNode, leftHash, rightHash) => ({
    nodeType: nodeTypes.parent,
    parentNode,
    leftHash,
    rightHash,
  }),
)

export const treeHashInputEncoder: BufferEncoder<TreeHashInput> = (input) => {
  switch (input.nodeType) {
    case nodeTypes.leaf:
      return leafNodeHashInputEncoder(input)
    case nodeTypes.parent:
      return parentNodeHashInputEncoder(input)
  }
}

export const decodeTreeHashInput: Decoder<TreeHashInput> = flatMapDecoder(
  decodeNodeType,
  (nodeType): Decoder<TreeHashInput> => {
    switch (nodeType) {
      case nodeTypes.leaf:
        return decodeLeafNodeHashInput
      case nodeTypes.parent:
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
    if (leafNode?.nodeType === nodeTypes.parent) throw new InternalError("Somehow found parent node in leaf position")
    const input = encode(leafNodeHashInputEncoder, {
      nodeType: nodeTypes.leaf,
      leafIndex: nodeToLeafIndex(subtreeIndex),
      leafNode: leafNode?.leaf,
    })
    return await h.digest(input)
  } else {
    const parentNode = tree[subtreeIndex]
    if (parentNode?.nodeType === nodeTypes.leaf) throw new InternalError("Somehow found leaf node in parent position")
    const leftHash = await treeHash(tree, left(subtreeIndex), h)
    const rightHash = await treeHash(tree, right(subtreeIndex), h)
    const input = {
      nodeType: nodeTypes.parent,
      parentNode: parentNode?.parent,
      leftHash: leftHash,
      rightHash: rightHash,
    } as const

    return await h.digest(encode(parentNodeHashInputEncoder, input))
  }
}
