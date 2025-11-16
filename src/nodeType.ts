import { decodeUint8, uint8Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

const nodeTypes = {
  leaf: 1,
  parent: 2,
} as const

export type NodeTypeName = keyof typeof nodeTypes
export type NodeTypeValue = (typeof nodeTypes)[NodeTypeName]

export const nodeTypeEncoder: BufferEncoder<NodeTypeName> = contramapBufferEncoder(uint8Encoder, (t) => nodeTypes[t])

export const encodeNodeType: Encoder<NodeTypeName> = encode(nodeTypeEncoder)

export const decodeNodeType: Decoder<NodeTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(nodeTypes))
