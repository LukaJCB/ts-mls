import { uint8Decoder, uint8Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { Encoder } from "./codec/tlsEncoder.js"

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

export const leafNodeSourceValueEncoder: Encoder<LeafNodeSourceValue> = uint8Encoder

export const leafNodeSourceValueDecoder: Decoder<LeafNodeSourceValue> = mapDecoderOption(uint8Decoder, (v) =>
  leafNodeSourceValues.has(v) ? (v as LeafNodeSourceValue) : undefined,
)
