import { encodeUint64, decodeUint64 } from "./codec/number"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"

export interface Lifetime {
  notBefore: bigint
  notAfter: bigint
}

export const encodeLifetime: Encoder<Lifetime> = contramapEncoders(
  [encodeUint64, encodeUint64],
  (lt) => [lt.notBefore, lt.notAfter] as const,
)

export const decodeLifetime: Decoder<Lifetime> = mapDecoders([decodeUint64, decodeUint64], (notBefore, notAfter) => ({
  notBefore,
  notAfter,
}))

export const defaultLifetime: Lifetime = {
  notBefore: 0n,
  notAfter: 9223372036854775807n,
}
