import { uint32Encoder, uint32Decoder } from "./codec/number.js"
import { optionalEncoder, optionalDecoder } from "./codec/optional.js"
import { Decoder, mapDecoders, flatMapDecoder } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders, encode } from "./codec/tlsEncoder.js"
import { varLenDataEncoder, varLenDataDecoder } from "./codec/variableLength.js"
import { Hash } from "./crypto/hash.js"
import { LeafNode, leafNodeEncoder, leafNodeDecoder } from "./leafNode.js"
import { InternalError } from "./mlsError.js"
import { nodeTypeDecoder, nodeTypeEncoder, nodeTypes } from "./nodeType.js"
import { ParentNode, parentNodeEncoder, parentNodeDecoder } from "./parentNode.js"
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

export const leafNodeHashInputDecoder: Decoder<LeafNodeHashInput> = mapDecoders(
  [uint32Decoder, optionalDecoder(leafNodeDecoder)],
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

export const parentNodeHashInputDecoder: Decoder<ParentNodeHashInput> = mapDecoders(
  [optionalDecoder(parentNodeDecoder), varLenDataDecoder, varLenDataDecoder],
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

export const treeHashInputDecoder: Decoder<TreeHashInput> = flatMapDecoder(
  nodeTypeDecoder,
  (nodeType): Decoder<TreeHashInput> => {
    switch (nodeType) {
      case nodeTypes.leaf:
        return leafNodeHashInputDecoder
      case nodeTypes.parent:
        return parentNodeHashInputDecoder
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
