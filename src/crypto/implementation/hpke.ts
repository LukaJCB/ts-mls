import { CipherSuite } from "@hpke/core"
import { Aead } from "../../crypto/aead.js"
import { HpkeAlgorithm, Hpke, PrivateKey, PublicKey } from "../../crypto/hpke.js"
import { concatUint8Arrays, bytesToArrayBuffer } from "../../util/byteArray.js"
import { CryptoError } from "../../mlsError.js"

export async function makeGenericHpke(hpkealg: HpkeAlgorithm, aead: Aead, cs: CipherSuite): Promise<Hpke> {
  return {
    async open(privateKey, kemOutput, ciphertext, info, aad) {
      try {
        const result = await cs.open(
          { recipientKey: privateKey, enc: bytesToArrayBuffer(kemOutput), info: bytesToArrayBuffer(info) },
          bytesToArrayBuffer(ciphertext),
          aad ? bytesToArrayBuffer(aad) : new ArrayBuffer(),
        )
        return new Uint8Array(result)
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },
    async seal(publicKey, plaintext, info, aad) {
      const result = await cs.seal(
        { recipientPublicKey: publicKey, info: bytesToArrayBuffer(info) },
        bytesToArrayBuffer(plaintext),
        aad ? bytesToArrayBuffer(aad) : new ArrayBuffer(),
      )
      return {
        ct: new Uint8Array(result.ct),
        enc: new Uint8Array(result.enc),
      }
    },
    async exportSecret(publicKey, exporterContext, length, info) {
      const context = await cs.createSenderContext({ recipientPublicKey: publicKey, info: bytesToArrayBuffer(info) })
      return {
        enc: new Uint8Array(context.enc),
        secret: new Uint8Array(await context.export(bytesToArrayBuffer(exporterContext), length)),
      }
    },
    async importSecret(privateKey, exporterContext, kemOutput, length, info) {
      try {
        const context = await cs.createRecipientContext({
          recipientKey: privateKey,
          info: bytesToArrayBuffer(info),
          enc: bytesToArrayBuffer(kemOutput),
        })
        return new Uint8Array(await context.export(bytesToArrayBuffer(exporterContext), length))
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },
    async importPrivateKey(k) {
      try {
        // See https://github.com/mlswg/mls-implementations/issues/176#issuecomment-1817043142
        const key = hpkealg.kem === "DHKEM-P521-HKDF-SHA512" ? prepadPrivateKeyP521(k) : k
        return (await cs.kem.deserializePrivateKey(bytesToArrayBuffer(key))) as PrivateKey
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },
    async importPublicKey(k) {
      try {
        return (await cs.kem.deserializePublicKey(bytesToArrayBuffer(k))) as PublicKey
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },
    async exportPublicKey(k) {
      return new Uint8Array(await cs.kem.serializePublicKey(k))
    },
    async exportPrivateKey(k) {
      return new Uint8Array(await cs.kem.serializePrivateKey(k))
    },
    async encryptAead(key, nonce, aad, plaintext) {
      return aead.encrypt(key, nonce, aad ? aad : new Uint8Array(), plaintext)
    },
    async decryptAead(key, nonce, aad, ciphertext) {
      try {
        return await aead.decrypt(key, nonce, aad ? aad : new Uint8Array(), ciphertext)
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },
    async deriveKeyPair(ikm) {
      const kp = await cs.kem.deriveKeyPair(bytesToArrayBuffer(ikm))
      return { privateKey: kp.privateKey as PrivateKey, publicKey: kp.publicKey as PublicKey }
    },
    async generateKeyPair() {
      const kp = await cs.kem.generateKeyPair()
      return { privateKey: kp.privateKey as PrivateKey, publicKey: kp.publicKey as PublicKey }
    },
    keyLength: cs.aead.keySize,
    nonceLength: cs.aead.nonceSize,
  }
}

function prepadPrivateKeyP521(k: Uint8Array) {
  const lengthDifference = 66 - k.byteLength
  return concatUint8Arrays(new Uint8Array(lengthDifference), k)
}
