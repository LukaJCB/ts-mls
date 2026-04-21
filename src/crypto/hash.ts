import { composeBufferEncoders, encode } from "../codec/tlsEncoder.js"
import { varLenDataEncoder } from "../codec/variableLength.js"

/** @public */
export type HashAlgorithm = "SHA-512" | "SHA-384" | "SHA-256"

/** @public */
export interface Hash {
  digest(data: Uint8Array): Promise<Uint8Array>
  mac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>
  verifyMac(key: Uint8Array, mac: Uint8Array, data: Uint8Array): Promise<boolean>
}

const _textEncoder = new TextEncoder()
const _refHashEncoder = composeBufferEncoders([varLenDataEncoder, varLenDataEncoder])

export function refhash(label: string, value: Uint8Array, h: Hash) {
  return h.digest(encodeRefHash(label, value))
}

function encodeRefHash(label: string, value: Uint8Array): Uint8Array {
  return encode(_refHashEncoder, [_textEncoder.encode(label), value])
}
