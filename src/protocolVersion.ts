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
export type ProtocolVersionValue = (typeof protocolVersions)[ProtocolVersionName]

export const protocolVersionEncoder: BufferEncoder<ProtocolVersionName> = contramapBufferEncoder(
  uint16Encoder,
  (t) => protocolVersions[t],
)

export const encodeProtocolVersion: Encoder<ProtocolVersionName> = encode(protocolVersionEncoder)

export const decodeProtocolVersion: Decoder<ProtocolVersionName> = mapDecoderOption(
  decodeUint16,
  enumNumberToKey(protocolVersions),
)
