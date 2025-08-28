import { decodeUint8, encodeUint8 } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapEncoder, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

const nodeTypes = {
  leaf: 1,
  parent: 2,
} as const

export type NodeTypeName = keyof typeof nodeTypes
export type NodeTypeValue = (typeof nodeTypes)[NodeTypeName]

export const encodeNodeType: Encoder<NodeTypeName> = contramapEncoder(encodeUint8, (t) => nodeTypes[t])

export const decodeNodeType: Decoder<NodeTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(nodeTypes))
