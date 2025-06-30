import { decodeUint16, encodeUint16 } from "./codec/number"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder"
import { contramapEncoder, Encoder } from "./codec/tlsEncoder"
import { enumNumberToKey } from "./util/enumHelpers"

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
