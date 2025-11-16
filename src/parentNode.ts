import { encUint32, decodeUint32 } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { Enc, contramapEncs } from "./codec/tlsEncoder.js"
import { encVarLenData, encVarLenType, decodeVarLenData, decodeVarLenType } from "./codec/variableLength.js"

export interface ParentNode {
  hpkePublicKey: Uint8Array
  parentHash: Uint8Array
  unmergedLeaves: number[]
}

export const encodeParentNode: Enc<ParentNode> = contramapEncs(
  [encVarLenData, encVarLenData, encVarLenType(encUint32)],
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
