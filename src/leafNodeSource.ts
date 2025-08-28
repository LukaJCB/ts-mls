import { decodeUint8, encodeUint8 } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapEncoder, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

const leafNodeSources = {
  key_package: 1,
  update: 2,
  commit: 3,
} as const

export type LeafNodeSourceName = keyof typeof leafNodeSources
export type LeafNodeSourceValue = (typeof leafNodeSources)[LeafNodeSourceName]

export const encodeLeafNodeSource: Encoder<LeafNodeSourceName> = contramapEncoder(
  encodeUint8,
  (t) => leafNodeSources[t],
)

export const decodeLeafNodeSource: Decoder<LeafNodeSourceName> = mapDecoderOption(
  decodeUint8,
  enumNumberToKey(leafNodeSources),
)
