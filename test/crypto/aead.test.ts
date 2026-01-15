import { makeAead as defaultMakeAead } from "../../src/crypto/implementation/default/makeAead.js"
import { makeAead as nobleMakeAead } from "../../src/crypto/implementation/noble/makeAead.js"

const key128 = crypto.getRandomValues(new Uint8Array(16))
const key256 = crypto.getRandomValues(new Uint8Array(32))
const nonce = crypto.getRandomValues(new Uint8Array(12))
const aad = crypto.getRandomValues(new Uint8Array(12))
const plaintext = new TextEncoder().encode("Hello world!")

describe("Default aead", () => {
  test("AES128-GCM encryption and decryption", async () => {
    const aead = await defaultMakeAead("AES128GCM")
    const ciphertext = await aead[0].encrypt(key128, nonce, new Uint8Array(), plaintext)
    const decrypted = await aead[0].decrypt(key128, nonce, new Uint8Array(), ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })

  test("AES256-GCM encryption and decryption", async () => {
    const aead = await defaultMakeAead("AES256GCM")
    const ciphertext = await aead[0].encrypt(key256, nonce, new Uint8Array(), plaintext)
    const decrypted = await aead[0].decrypt(key256, nonce, new Uint8Array(), ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })

  test("ChaCha20-Poly1305 encryption and decryption", async () => {
    const aead = await defaultMakeAead("CHACHA20POLY1305")
    const ciphertext = await aead[0].encrypt(key256, nonce, new Uint8Array(), plaintext)
    const decrypted = await aead[0].decrypt(key256, nonce, new Uint8Array(), ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })

  test("AES128-GCM encryption and decryption with aad", async () => {
    const aead = await defaultMakeAead("AES128GCM")
    const ciphertext = await aead[0].encrypt(key128, nonce, aad, plaintext)
    const decrypted = await aead[0].decrypt(key128, nonce, aad, ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })

  test("AES256-GCM encryption and decryption with aad", async () => {
    const aead = await defaultMakeAead("AES256GCM")
    const ciphertext = await aead[0].encrypt(key256, nonce, aad, plaintext)
    const decrypted = await aead[0].decrypt(key256, nonce, aad, ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })

  test("ChaCha20-Poly1305 encryption and decryption with aad", async () => {
    const aead = await defaultMakeAead("CHACHA20POLY1305")
    const ciphertext = await aead[0].encrypt(key256, nonce, aad, plaintext)
    const decrypted = await aead[0].decrypt(key256, nonce, aad, ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })
})

describe("Noble aead implementation", () => {
  test("AES128-GCM encryption and decryption", async () => {
    const aead = await nobleMakeAead("AES128GCM")
    const ciphertext = await aead[0].encrypt(key128, nonce, new Uint8Array(), plaintext)
    const decrypted = await aead[0].decrypt(key128, nonce, new Uint8Array(), ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })

  test("AES256-GCM encryption and decryption", async () => {
    const aead = await nobleMakeAead("AES256GCM")
    const ciphertext = await aead[0].encrypt(key256, nonce, new Uint8Array(), plaintext)
    const decrypted = await aead[0].decrypt(key256, nonce, new Uint8Array(), ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })

  test("ChaCha20-Poly1305 encryption and decryption", async () => {
    const aead = await nobleMakeAead("CHACHA20POLY1305")
    const ciphertext = await aead[0].encrypt(key256, nonce, new Uint8Array(), plaintext)
    const decrypted = await aead[0].decrypt(key256, nonce, new Uint8Array(), ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })

  test("AES128-GCM encryption and decryption with aad", async () => {
    const aead = await nobleMakeAead("AES128GCM")
    const ciphertext = await aead[0].encrypt(key128, nonce, aad, plaintext)
    const decrypted = await aead[0].decrypt(key128, nonce, aad, ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })

  test("AES256-GCM encryption and decryption with aad", async () => {
    const aead = await nobleMakeAead("AES256GCM")
    const ciphertext = await aead[0].encrypt(key256, nonce, aad, plaintext)
    const decrypted = await aead[0].decrypt(key256, nonce, aad, ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })

  test("ChaCha20-Poly1305 encryption and decryption with aad", async () => {
    const aead = await nobleMakeAead("CHACHA20POLY1305")
    const ciphertext = await aead[0].encrypt(key256, nonce, aad, plaintext)
    const decrypted = await aead[0].decrypt(key256, nonce, aad, ciphertext)

    expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
  })
})
