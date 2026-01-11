import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

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

export const encodeProtocolVersion: Encoder<ProtocolVersionValue> = encode(protocolVersionEncoder)

export const decodeProtocolVersion: Decoder<ProtocolVersionValue> = mapDecoderOption(decodeUint16, (v) =>
  protocolVersionValues.has(v) ? (v as ProtocolVersionValue) : undefined,
)

export const protocolVersionNameEncoder: BufferEncoder<ProtocolVersionName> = contramapBufferEncoder(
  uint16Encoder,
  (t) => protocolVersions[t],
)

export const encodeProtocolVersionName: Encoder<ProtocolVersionName> = encode(protocolVersionNameEncoder)

export const decodeProtocolVersionName: Decoder<ProtocolVersionName> = mapDecoderOption(
  decodeUint16,
  enumNumberToKey(protocolVersions),
)
