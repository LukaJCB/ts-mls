import { uint64Encoder, decodeUint64 } from "./codec/number.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"

/** @public */
export interface Lifetime {
  notBefore: bigint
  notAfter: bigint
}

export const lifetimeEncoder: BufferEncoder<Lifetime> = contramapBufferEncoders(
  [uint64Encoder, uint64Encoder],
  (lt) => [lt.notBefore, lt.notAfter] as const,
)

export const decodeLifetime: Decoder<Lifetime> = mapDecoders([decodeUint64, decodeUint64], (notBefore, notAfter) => ({
  notBefore,
  notAfter,
}))

/** @public */
export const defaultLifetime: Lifetime = {
  notBefore: 0n,
  notAfter: 9223372036854775807n,
}
