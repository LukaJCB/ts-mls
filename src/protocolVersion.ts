import { decodeUint16, encodeUint16 } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapEncoder, Encoder } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

export const protocolVersions = {
  mls10: 1,
} as const

export type ProtocolVersionName = keyof typeof protocolVersions
export type ProtocolVersionValue = (typeof protocolVersions)[ProtocolVersionName]

export const encodeProtocolVersion: Encoder<ProtocolVersionName> = contramapEncoder(
  encodeUint16,
  (t) => protocolVersions[t],
)

export const decodeProtocolVersion: Decoder<ProtocolVersionName> = mapDecoderOption(
  decodeUint16,
  enumNumberToKey(protocolVersions),
)
