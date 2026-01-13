import { decodeUint8, uint8Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { BufferEncoder } from "./codec/tlsEncoder.js"

/** @public */
export const leafNodeSources = {
  key_package: 1,
  update: 2,
  commit: 3,
} as const

/** @public */
export type LeafNodeSourceName = keyof typeof leafNodeSources
/** @public */
export type LeafNodeSourceValue = (typeof leafNodeSources)[LeafNodeSourceName]

const leafNodeSourceValues = new Set<number>(Object.values(leafNodeSources))

export const leafNodeSourceValueEncoder: BufferEncoder<LeafNodeSourceValue> = uint8Encoder

export const decodeLeafNodeSourceValue: Decoder<LeafNodeSourceValue> = mapDecoderOption(decodeUint8, (v) =>
  leafNodeSourceValues.has(v) ? (v as LeafNodeSourceValue) : undefined,
)
