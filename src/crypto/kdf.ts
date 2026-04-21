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

const _textEncoder = new TextEncoder()
const _infoEncoder = composeBufferEncoders([uint16Encoder, varLenDataEncoder, varLenDataEncoder])
const _emptyContext = new Uint8Array(0)
const _labelCache = new Map<string, Uint8Array>()

function labelBytes(label: string): Uint8Array {
  let bytes = _labelCache.get(label)
  if (bytes === undefined) {
    bytes = _textEncoder.encode(`MLS 1.0 ${label}`)
    _labelCache.set(label, bytes)
  }
  return bytes
}

export function expandWithLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
  kdf: Kdf,
): Promise<Uint8Array> {
  return kdf.expand(secret, encode(_infoEncoder, [length, labelBytes(label), context]), length)
}

export async function deriveSecret(secret: Uint8Array, label: string, kdf: Kdf): Promise<Uint8Array> {
  return expandWithLabel(secret, label, _emptyContext, kdf.size, kdf)
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
