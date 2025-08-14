import { utf8ToBytes } from "@noble/ciphers/utils"
import { encodeVarLenData } from "../codec/variableLength"
import { bytesToBuffer, concatUint8Arrays } from "../util/byteArray"

export type HashAlgorithm = "SHA-512" | "SHA-384" | "SHA-256"

export function makeHashImpl(sc: SubtleCrypto, h: HashAlgorithm): Hash {
  return {
    async digest(data) {
      const result = await sc.digest(h, bytesToBuffer(data))
      return new Uint8Array(result)
    },
    async mac(key, data) {
      const result = await sc.sign("HMAC", await importMacKey(key, h), bytesToBuffer(data))
      return new Uint8Array(result)
    },
    async verifyMac(key, mac, data) {
      return sc.verify("HMAC", await importMacKey(key, h), bytesToBuffer(mac), bytesToBuffer(data))
    },
  }
}

function importMacKey(rawKey: Uint8Array, h: HashAlgorithm): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    bytesToBuffer(rawKey),
    {
      name: "HMAC",
      hash: { name: h },
    },
    false,
    ["sign", "verify"],
  )
}

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
