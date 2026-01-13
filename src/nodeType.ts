import { decodeUint8, uint8Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { numberToEnum } from "./util/enumHelpers.js"

export const nodeTypes = {
  leaf: 1,
  parent: 2,
} as const

export type NodeTypeName = keyof typeof nodeTypes
export type NodeTypeValue = (typeof nodeTypes)[NodeTypeName]

export const nodeTypeEncoder: BufferEncoder<NodeTypeValue> = uint8Encoder

export const encodeNodeType: Encoder<NodeTypeValue> = encode(nodeTypeEncoder)

export const decodeNodeType: Decoder<NodeTypeValue> = mapDecoderOption(decodeUint8, numberToEnum(nodeTypes))
