import { utf8ToBytes } from "@noble/ciphers/utils"
import { encodeVarLenData } from "../codec/variableLength"
import { concatUint8Arrays } from "../util/byteArray"

export type HashAlgorithm = "SHA-512" | "SHA-384" | "SHA-256"

export interface Hash {
  digest(data: Uint8Array): Promise<Uint8Array>
  mac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>
  verifyMac(key: Uint8Array, mac: Uint8Array, data: Uint8Array): Promise<boolean>
}

export function refhash(label: string, value: Uint8Array, h: Hash) {
  return h.digest(encodeRefHash(label, value))
}

function encodeRefHash(label: string, value: Uint8Array): Uint8Array {
  const labelBytes = utf8ToBytes(label)
  return concatUint8Arrays(encodeVarLenData(labelBytes), encodeVarLenData(value))
}
