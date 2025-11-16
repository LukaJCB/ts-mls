import { encVarLenData } from "../codec/variableLength.js"
import { encUint16, encUint32 } from "../codec/number.js"
import { concat3Uint8Arrays } from "../util/byteArray.js"
import { encode } from "../codec/tlsEncoder.js"

export interface Kdf {
  extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>
  expand(prk: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array>
  size: number
}

export type KdfAlgorithm = "HKDF-SHA256" | "HKDF-SHA384" | "HKDF-SHA512"

export function expandWithLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
  kdf: Kdf,
): Promise<Uint8Array> {
  return kdf.expand(
    secret,
    concat3Uint8Arrays(
      encode(encUint16)(length),
      encode(encVarLenData)(new TextEncoder().encode(`MLS 1.0 ${label}`)),
      encode(encVarLenData)(context),
    ), //todo
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
  return expandWithLabel(secret, label, encode(encUint32)(generation), length, kdf)
}
