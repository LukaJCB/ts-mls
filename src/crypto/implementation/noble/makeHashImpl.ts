import { HashAlgorithm, Hash } from "../../hash.js"
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js"
import { hmac } from "@noble/hashes/hmac.js"

export function makeHashImpl(h: HashAlgorithm): Hash {
  return {
    async digest(data) {
      switch (h) {
        case "SHA-256":
          return sha256(data)
        case "SHA-384":
          return sha384(data)
        case "SHA-512":
          return sha512(data)
        default:
          throw new Error(`Unsupported hash algorithm: ${h}`)
      }
    },
    async mac(key, data) {
      switch (h) {
        case "SHA-256":
          return hmac(sha256, key, data)
        case "SHA-384":
          return hmac(sha384, key, data)
        case "SHA-512":
          return hmac(sha512, key, data)
        default:
          throw new Error(`Unsupported hash algorithm: ${h}`)
      }
    },
    async verifyMac(key, mac, data) {
      const expectedMac = await this.mac(key, data)
      return mac.length === expectedMac.length && mac.every((byte, i) => byte === expectedMac[i])
    },
  }
}
