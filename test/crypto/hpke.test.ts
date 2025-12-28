import { Hpke, PrivateKey } from "../../src/crypto/hpke.js"
import { makeHpke as defaultMakeHpke } from "../../src/crypto/implementation/default/makeHpke.js"
import { makeHpke as nobleMakeHpke } from "../../src/crypto/implementation/noble/makeHpke.js"
import { CryptoError } from "../../src/mlsError.js"

// Use a minimal valid algorithm config (using a likely supported one)
const hpkeAlg = {
  kem: "DHKEM-P256-HKDF-SHA256",
  kdf: "HKDF-SHA256",
  aead: "AES128GCM",
} as const

describe("Default hpke error handling", () => {
  let hpke: Hpke
  let secKey: PrivateKey
  beforeAll(async () => {
    hpke = await defaultMakeHpke(hpkeAlg)
    const { privateKey } = await hpke.generateKeyPair()
    secKey = privateKey
  })

  test("throws CryptoError from open (invalid ciphertext)", async () => {
    await expect(hpke.open(secKey, new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3]))).rejects.toThrow(
      CryptoError,
    )
  })

  test("throws CryptoError from importSecret (invalid kemOutput)", async () => {
    await expect(
      hpke.importSecret(secKey, new Uint8Array([1]), new Uint8Array([2]), 16, new Uint8Array([3])),
    ).rejects.toThrow(CryptoError)
  })

  test("throws CryptoError from importPrivateKey (invalid key)", async () => {
    await expect(hpke.importPrivateKey(new Uint8Array([1, 2, 3]))).rejects.toThrow(CryptoError)
  })

  test("throws CryptoError from importPublicKey (invalid key)", async () => {
    await expect(hpke.importPublicKey(new Uint8Array([1, 2, 3]))).rejects.toThrow(CryptoError)
  })

  test("throws CryptoError from decryptAead (invalid key/nonce)", async () => {
    await expect(
      hpke.decryptAead(new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3]), new Uint8Array([4])),
    ).rejects.toThrow(CryptoError)
  })
})

describe("Default hpke happy path", () => {
  let hpke: Hpke
  beforeAll(async () => {
    hpke = await defaultMakeHpke(hpkeAlg)
  })

  test("can seal and open a message", async () => {
    const { publicKey, privateKey } = await hpke.generateKeyPair()
    const plaintext = new TextEncoder().encode("hello world")
    const info = new TextEncoder().encode("test info")
    const { ct, enc } = await hpke.seal(publicKey, plaintext, info)
    const decrypted = await hpke.open(privateKey, enc, ct, info)
    expect(new TextDecoder().decode(decrypted)).toBe("hello world")
  })

  test("can seal and open a message with aad", async () => {
    const { publicKey, privateKey } = await hpke.generateKeyPair()
    const plaintext = new TextEncoder().encode("hello world")
    const info = new TextEncoder().encode("test info")
    const aad = new TextEncoder().encode("additional data")
    const { ct, enc } = await hpke.seal(publicKey, plaintext, info, aad)
    const decrypted = await hpke.open(privateKey, enc, ct, info, aad)
    expect(new TextDecoder().decode(decrypted)).toBe("hello world")
  })

  test("can encrypt and decrypt with AEAD", async () => {
    const key = new Uint8Array(hpke.keyLength)
    const nonce = new Uint8Array(hpke.nonceLength)
    const aad = new TextEncoder().encode("aad")
    const plaintext = new TextEncoder().encode("secret")
    const ciphertext = await hpke.encryptAead(key, nonce, aad, plaintext)
    const decrypted = await hpke.decryptAead(key, nonce, aad, ciphertext)
    expect(new TextDecoder().decode(decrypted)).toBe("secret")
  })
})

describe("Noble hpke error handling", () => {
  let hpke: Hpke
  let secKey: PrivateKey
  beforeAll(async () => {
    hpke = await defaultMakeHpke(hpkeAlg)
    const { privateKey } = await hpke.generateKeyPair()
    secKey = privateKey
  })

  test("throws CryptoError from open (invalid ciphertext)", async () => {
    await expect(hpke.open(secKey, new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3]))).rejects.toThrow(
      CryptoError,
    )
  })

  test("throws CryptoError from importSecret (invalid kemOutput)", async () => {
    await expect(
      hpke.importSecret(secKey, new Uint8Array([1]), new Uint8Array([2]), 16, new Uint8Array([3])),
    ).rejects.toThrow(CryptoError)
  })

  test("throws CryptoError from importPrivateKey (invalid key)", async () => {
    await expect(hpke.importPrivateKey(new Uint8Array([1, 2, 3]))).rejects.toThrow(CryptoError)
  })

  test("throws CryptoError from importPublicKey (invalid key)", async () => {
    await expect(hpke.importPublicKey(new Uint8Array([1, 2, 3]))).rejects.toThrow(CryptoError)
  })

  test("throws CryptoError from decryptAead (invalid key/nonce)", async () => {
    await expect(
      hpke.decryptAead(new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3]), new Uint8Array([4])),
    ).rejects.toThrow(CryptoError)
  })
})

describe("Noble hpke happy path", () => {
  let hpke: Hpke
  beforeAll(async () => {
    hpke = await nobleMakeHpke(hpkeAlg)
  })

  test("can seal and open a message", async () => {
    const { publicKey, privateKey } = await hpke.generateKeyPair()
    const plaintext = new TextEncoder().encode("hello world")
    const info = new TextEncoder().encode("test info")
    const { ct, enc } = await hpke.seal(publicKey, plaintext, info)
    const decrypted = await hpke.open(privateKey, enc, ct, info)
    expect(new TextDecoder().decode(decrypted)).toBe("hello world")
  })

  test("can encrypt and decrypt with AEAD", async () => {
    const key = new Uint8Array(hpke.keyLength)
    const nonce = new Uint8Array(hpke.nonceLength)
    const aad = new TextEncoder().encode("aad")
    const plaintext = new TextEncoder().encode("secret")
    const ciphertext = await hpke.encryptAead(key, nonce, aad, plaintext)
    const decrypted = await hpke.decryptAead(key, nonce, aad, ciphertext)
    expect(new TextDecoder().decode(decrypted)).toBe("secret")
  })

  test("can seal and open a message with aad", async () => {
    const { publicKey, privateKey } = await hpke.generateKeyPair()
    const plaintext = new TextEncoder().encode("hello world")
    const info = new TextEncoder().encode("test info")
    const aad = new TextEncoder().encode("additional data")
    const { ct, enc } = await hpke.seal(publicKey, plaintext, info, aad)
    const decrypted = await hpke.open(privateKey, enc, ct, info, aad)
    expect(new TextDecoder().decode(decrypted)).toBe("hello world")
  })
})
