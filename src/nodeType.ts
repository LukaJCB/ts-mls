import { uint8Decoder, uint8Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { BufferEncoder } from "./codec/tlsEncoder.js"
import { numberToEnum } from "./util/enumHelpers.js"

export const nodeTypes = {
  leaf: 1,
  parent: 2,
} as const

export type NodeTypeName = keyof typeof nodeTypes
export type NodeTypeValue = (typeof nodeTypes)[NodeTypeName]

export const nodeTypeEncoder: BufferEncoder<NodeTypeValue> = uint8Encoder

export const nodeTypeDecoder: Decoder<NodeTypeValue> = mapDecoderOption(uint8Decoder, numberToEnum(nodeTypes))
