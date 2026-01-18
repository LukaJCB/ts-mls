import { uint64Encoder, uint64Decoder } from "./codec/number.js"
import { Encoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"

/** @public */
export interface Lifetime {
  notBefore: bigint
  notAfter: bigint
}

export const lifetimeEncoder: Encoder<Lifetime> = contramapBufferEncoders(
  [uint64Encoder, uint64Encoder],
  (lt) => [lt.notBefore, lt.notAfter] as const,
)

export const lifetimeDecoder: Decoder<Lifetime> = mapDecoders(
  [uint64Decoder, uint64Decoder],
  (notBefore, notAfter) => ({
    notBefore,
    notAfter,
  }),
)

/** @public */
export function defaultLifetime(): Lifetime {
  const now = Math.floor(Date.now() / 1000)
  return {
    notBefore: BigInt(now - 86400),
    notAfter: BigInt(now + 1314000), // Half month
  }
}
