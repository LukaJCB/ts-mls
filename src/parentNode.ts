import { uint32Encoder, decodeUint32 } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { varLenDataEncoder, varLenTypeEncoder, decodeVarLenData, decodeVarLenType } from "./codec/variableLength.js"

/** @public */
export interface ParentNode {
  hpkePublicKey: Uint8Array
  parentHash: Uint8Array
  unmergedLeaves: number[]
}

export const parentNodeEncoder: BufferEncoder<ParentNode> = contramapBufferEncoders(
  [varLenDataEncoder, varLenDataEncoder, varLenTypeEncoder(uint32Encoder)],
  (node) => [node.hpkePublicKey, node.parentHash, node.unmergedLeaves] as const,
)

export const decodeParentNode: Decoder<ParentNode> = mapDecoders(
  [decodeVarLenData, decodeVarLenData, decodeVarLenType(decodeUint32)],
  (hpkePublicKey, parentHash, unmergedLeaves) => ({
    hpkePublicKey,
    parentHash,
    unmergedLeaves,
  }),
)
