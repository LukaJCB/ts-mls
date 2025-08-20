import { AeadInterface, Aes128Gcm, Aes256Gcm } from "@hpke/core"
import { DependencyError } from "../../../mlsError"
import { bytesToBuffer } from "../../../util/byteArray"
import { AeadAlgorithm, Aead } from "../../aead"

export async function makeAead(aeadAlg: AeadAlgorithm): Promise<[Aead, AeadInterface]> {
  switch (aeadAlg) {
    case "AES128GCM":
      return [
        {
          encrypt(key, nonce, aad, plaintext) {
            return encryptAesGcm(key, nonce, aad, plaintext)
          },
          decrypt(key, nonce, aad, ciphertext) {
            return decryptAesGcm(key, nonce, aad, ciphertext)
          },
        },
        new Aes128Gcm(),
      ]
    case "AES256GCM":
      return [
        {
          encrypt(key, nonce, aad, plaintext) {
            return encryptAesGcm(key, nonce, aad, plaintext)
          },
          decrypt(key, nonce, aad, ciphertext) {
            return decryptAesGcm(key, nonce, aad, ciphertext)
          },
        },
        new Aes256Gcm(),
      ]
    case "CHACHA20POLY1305":
      try {
        const { Chacha20Poly1305 } = await import("@hpke/chacha20poly1305")
        const { chacha20poly1305 } = await import("@noble/ciphers/chacha")
        return [
          {
            async encrypt(key, nonce, aad, plaintext) {
              return chacha20poly1305(key, nonce, aad).encrypt(plaintext)
            },
            async decrypt(key, nonce, aad, ciphertext) {
              return chacha20poly1305(key, nonce, aad).decrypt(ciphertext)
            },
          },
          new Chacha20Poly1305(),
        ]
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@hpke/chacha20poly1305' is not installed. Please install it to use this feature.",
        )
      }
  }
}

async function encryptAesGcm(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey("raw", bytesToBuffer(key), { name: "AES-GCM" }, false, ["encrypt"])
  const result = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: bytesToBuffer(nonce),
      additionalData: aad.length > 0 ? bytesToBuffer(aad) : undefined,
    },
    cryptoKey,
    bytesToBuffer(plaintext),
  )
  return new Uint8Array(result)
}

async function decryptAesGcm(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey("raw", bytesToBuffer(key), { name: "AES-GCM" }, false, ["decrypt"])
  const result = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bytesToBuffer(nonce),
      additionalData: aad.length > 0 ? bytesToBuffer(aad) : undefined,
    },
    cryptoKey,
    bytesToBuffer(ciphertext),
  )
  return new Uint8Array(result)
}
