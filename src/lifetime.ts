import { encUint64, decodeUint64 } from "./codec/number.js"
import { Enc, contramapEncs } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"

export interface Lifetime {
  notBefore: bigint
  notAfter: bigint
}

export const encodeLifetime: Enc<Lifetime> = contramapEncs(
  [encUint64, encUint64],
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
