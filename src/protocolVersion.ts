import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { BufferEncoder } from "./codec/tlsEncoder.js"

/** @public */
export const protocolVersions = {
  mls10: 1,
} as const

/** @public */
export type ProtocolVersionName = keyof typeof protocolVersions
/** @public */
export type ProtocolVersionValue = (typeof protocolVersions)[ProtocolVersionName]

const protocolVersionValues = new Set<number>(Object.values(protocolVersions))

export const protocolVersionEncoder: BufferEncoder<ProtocolVersionValue> = uint16Encoder

export const decodeProtocolVersion: Decoder<ProtocolVersionValue> = mapDecoderOption(decodeUint16, (v) =>
  protocolVersionValues.has(v) ? (v as ProtocolVersionValue) : undefined,
)
