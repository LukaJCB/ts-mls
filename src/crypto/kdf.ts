import { varLenDataEncoder } from "../codec/variableLength.js"
import { uint16Encoder, uint32Encoder } from "../codec/number.js"
import { composeBufferEncoders, encode } from "../codec/tlsEncoder.js"

/** @public */
export interface Kdf {
  extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>
  expand(prk: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array>
  size: number
}

/** @public */
export type KdfAlgorithm = "HKDF-SHA256" | "HKDF-SHA384" | "HKDF-SHA512"

export function expandWithLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
  kdf: Kdf,
): Promise<Uint8Array> {
  const infoEncoder = composeBufferEncoders([uint16Encoder, varLenDataEncoder, varLenDataEncoder])
  return kdf.expand(
    secret,
    encode(infoEncoder, [length, new TextEncoder().encode(`MLS 1.0 ${label}`), context]),
    length,
  )
}

export async function deriveSecret(secret: Uint8Array, label: string, kdf: Kdf): Promise<Uint8Array> {
  return expandWithLabel(secret, label, new Uint8Array(), kdf.size, kdf)
}

export async function deriveTreeSecret(
  secret: Uint8Array,
  label: string,
  generation: number,
  length: number,
  kdf: Kdf,
): Promise<Uint8Array> {
  return expandWithLabel(secret, label, encode(uint32Encoder, generation), length, kdf)
}
