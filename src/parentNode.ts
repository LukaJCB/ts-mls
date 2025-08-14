import { encodeUint32, decodeUint32 } from "./codec/number"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder"
import { encodeVarLenData, encodeVarLenType, decodeVarLenData, decodeVarLenType } from "./codec/variableLength"

export interface ParentNode {
  hpkePublicKey: Uint8Array
  parentHash: Uint8Array
  unmergedLeaves: number[]
}

export const encodeParentNode: Encoder<ParentNode> = contramapEncoders(
  [encodeVarLenData, encodeVarLenData, encodeVarLenType(encodeUint32)],
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
