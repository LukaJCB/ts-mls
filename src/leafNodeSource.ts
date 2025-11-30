import { decodeUint8, uint8Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

const leafNodeSources = {
  key_package: 1,
  update: 2,
  commit: 3,
} as const

export type LeafNodeSourceName = keyof typeof leafNodeSources
export type LeafNodeSourceValue = (typeof leafNodeSources)[LeafNodeSourceName]

export const leafNodeSourceEncoder: BufferEncoder<LeafNodeSourceName> = contramapBufferEncoder(
  uint8Encoder,
  (t) => leafNodeSources[t],
)

export const encodeLeafNodeSource: Encoder<LeafNodeSourceName> = encode(leafNodeSourceEncoder)

export const decodeLeafNodeSource: Decoder<LeafNodeSourceName> = mapDecoderOption(
  decodeUint8,
  enumNumberToKey(leafNodeSources),
)
