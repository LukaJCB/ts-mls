import { Aes128Gcm, Aes256Gcm } from "@hpke/core"
import { AeadInterface } from "@hpke/core"
import { bytesToBuffer } from "../util/byteArray"
import { DependencyError } from "../mlsError"

export type AeadAlgorithm = "AES128GCM" | "CHACHA20POLY1305" | "AES256GCM"

export interface Aead {
  hpkeInterface(): AeadInterface
  encrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>
  decrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>
}

export async function makeAead(aeadAlg: AeadAlgorithm): Promise<Aead> {
  switch (aeadAlg) {
    case "AES128GCM":
      return {
        hpkeInterface() {
          return new Aes128Gcm()
        },
        encrypt(key, nonce, aad, plaintext) {
          return encryptAesGcm(key, nonce, aad, plaintext)
        },
        decrypt(key, nonce, aad, ciphertext) {
          return decryptAesGcm(key, nonce, aad, ciphertext)
        },
      }
    case "AES256GCM":
      return {
        hpkeInterface() {
          return new Aes256Gcm()
        },
        encrypt(key, nonce, aad, plaintext) {
          return encryptAesGcm(key, nonce, aad, plaintext)
        },
        decrypt(key, nonce, aad, ciphertext) {
          return decryptAesGcm(key, nonce, aad, ciphertext)
        },
      }
    case "CHACHA20POLY1305":
      try {
        const { Chacha20Poly1305 } = await import("@hpke/chacha20poly1305")
        const { chacha20poly1305 } = await import("@noble/ciphers/chacha")
        return {
          hpkeInterface() {
            return new Chacha20Poly1305()
          },
          async encrypt(key, nonce, aad, plaintext) {
            return chacha20poly1305(key, nonce, aad).encrypt(plaintext)
          },
          async decrypt(key, nonce, aad, ciphertext) {
            return chacha20poly1305(key, nonce, aad).decrypt(ciphertext)
          },
        }
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
