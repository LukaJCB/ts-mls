import { makeAead } from "../../src/crypto/implementation/default/makeAead"
import { randomBytes } from "crypto"

const key128 = randomBytes(16)
const key256 = randomBytes(32)
const nonce = randomBytes(12)
const aad = randomBytes(12)
const plaintext = new TextEncoder().encode("Hello world!")

test("AES128-GCM encryption and decryption", async () => {
  const aead = await makeAead("AES128GCM")
  const ciphertext = await aead[0].encrypt(key128, nonce, new Uint8Array(), plaintext)
  const decrypted = await aead[0].decrypt(key128, nonce, new Uint8Array(), ciphertext)

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})

test("AES256-GCM encryption and decryption", async () => {
  const aead = await makeAead("AES256GCM")
  const ciphertext = await aead[0].encrypt(key256, nonce, new Uint8Array(), plaintext)
  const decrypted = await aead[0].decrypt(key256, nonce, new Uint8Array(), ciphertext)

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})

test("ChaCha20-Poly1305 encryption and decryption", async () => {
  const aead = await makeAead("CHACHA20POLY1305")
  const ciphertext = await aead[0].encrypt(key256, nonce, new Uint8Array(), plaintext)
  const decrypted = await aead[0].decrypt(key256, nonce, new Uint8Array(), ciphertext)

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})

test("AES128-GCM encryption and decryption with aad", async () => {
  const aead = await makeAead("AES128GCM")
  const ciphertext = await aead[0].encrypt(key128, nonce, aad, plaintext)
  const decrypted = await aead[0].decrypt(key128, nonce, aad, ciphertext)

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})

test("AES256-GCM encryption and decryption with aad", async () => {
  const aead = await makeAead("AES256GCM")
  const ciphertext = await aead[0].encrypt(key256, nonce, aad, plaintext)
  const decrypted = await aead[0].decrypt(key256, nonce, aad, ciphertext)

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})

test("ChaCha20-Poly1305 encryption and decryption with aad", async () => {
  const aead = await makeAead("CHACHA20POLY1305")
  const ciphertext = await aead[0].encrypt(key256, nonce, aad, plaintext)
  const decrypted = await aead[0].decrypt(key256, nonce, aad, ciphertext)

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})
