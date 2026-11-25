import { uint64Encoder, uint64Decoder } from "./codec/number.js"
import { Encoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { LifetimeConfig } from "./lifetimeConfig.js"
import { ValidationError } from "./mlsError.js"

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

export function validateLifetime(
  lifetime: Lifetime,
  config: LifetimeConfig,
  sentByClient: boolean,
): ValidationError | undefined {
  const { notBefore, notAfter } = lifetime
  if (notAfter < notBefore) return new ValidationError("Lifetime notAfter must not be before notBefore")
  if (notAfter - notBefore > config.maximumTotalLifetime)
    return new ValidationError("Lifetime exceeds maximum total lifetime")

  if (sentByClient || config.validateLifetimeOnReceive) {
    const currentTime = BigInt(Math.floor(Date.now() / 1000))
    if (notBefore > currentTime || notAfter < currentTime)
      return new ValidationError("Current time not within Lifetime")
  }
}
