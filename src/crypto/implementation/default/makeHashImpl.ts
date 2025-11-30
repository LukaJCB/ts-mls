import { toBufferSource } from "../../../util/byteArray.js"
import { HashAlgorithm, Hash } from "../../hash.js"

export function makeHashImpl(sc: SubtleCrypto, h: HashAlgorithm): Hash {
  return {
    async digest(data) {
      const result = await sc.digest(h, toBufferSource(data))
      return new Uint8Array(result)
    },
    async mac(key, data) {
      const result = await sc.sign("HMAC", await importMacKey(key, h), toBufferSource(data))
      return new Uint8Array(result)
    },
    async verifyMac(key, mac, data) {
      return sc.verify("HMAC", await importMacKey(key, h), toBufferSource(mac), toBufferSource(data))
    },
  }
}
function importMacKey(rawKey: Uint8Array, h: HashAlgorithm): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toBufferSource(rawKey),
    {
      name: "HMAC",
      hash: { name: h },
    },
    false,
    ["sign", "verify"],
  )
}
