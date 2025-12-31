import { DependencyError } from "../../../mlsError.js"
import { SignatureAlgorithm, Signature } from "../../signature.js"
import { toBufferSource } from "../../../util/byteArray.js"

function rawEd25519ToPKCS8(rawKey: Uint8Array): Uint8Array {
  const oid = new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x70])

  const innerOctetString = new Uint8Array([0x04, 0x20, ...rawKey])

  const privateKeyField = new Uint8Array([0x04, 0x22, ...innerOctetString])
  const algorithmSeq = new Uint8Array([0x30, 0x05, ...oid])

  const version = new Uint8Array([0x02, 0x01, 0x00])

  const content = new Uint8Array([...version, ...algorithmSeq, ...privateKeyField])

  return new Uint8Array([0x30, content.length, ...content])
}

export async function makeNobleSignatureImpl(alg: SignatureAlgorithm): Promise<Signature> {
  switch (alg) {
    case "Ed25519": {
      const subtle = globalThis.crypto?.subtle

      if (subtle !== undefined) {
        return {
          async sign(signKey, message) {
            const keyData = signKey.length === 32 ? rawEd25519ToPKCS8(signKey) : signKey
            const key = await subtle.importKey("pkcs8", toBufferSource(keyData), "Ed25519", false, ["sign"])
            const sig = await subtle.sign("Ed25519", key, toBufferSource(message))
            return new Uint8Array(sig)
          },
          async verify(publicKey, message, signature) {
            const key = await subtle.importKey("raw", toBufferSource(publicKey), "Ed25519", false, ["verify"])
            return subtle.verify("Ed25519", key, toBufferSource(signature), toBufferSource(message))
          },
          async keygen() {
            const keyPair = await subtle.generateKey("Ed25519", true, ["sign", "verify"])
            const publicKeyBuffer = await subtle.exportKey("raw", keyPair.publicKey)
            const privateKeyBuffer = await subtle.exportKey("pkcs8", keyPair.privateKey)

            const publicKey = new Uint8Array(publicKeyBuffer)
            const signKey = new Uint8Array(privateKeyBuffer)

            return { signKey, publicKey }
          },
        }
      }

      try {
        const { ed25519 } = await import("@noble/curves/ed25519.js")
        return {
          async sign(signKey, message) {
            return ed25519.sign(message, signKey)
          },
          async verify(publicKey, message, signature) {
            return ed25519.verify(signature, message, publicKey)
          },
          async keygen() {
            const signKey = ed25519.utils.randomSecretKey()
            return { signKey, publicKey: ed25519.getPublicKey(signKey) }
          },
        }
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@noble/curves' is not installed. Please install it to use this feature.",
        )
      }
    }

    case "Ed448":
      try {
        const { ed448 } = await import("@noble/curves/ed448.js")
        return {
          async sign(signKey, message) {
            return ed448.sign(message, signKey)
          },
          async verify(publicKey, message, signature) {
            return ed448.verify(signature, message, publicKey)
          },
          async keygen() {
            const signKey = ed448.utils.randomSecretKey()
            return { signKey, publicKey: ed448.getPublicKey(signKey) }
          },
        }
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@noble/curves' is not installed. Please install it to use this feature.",
        )
      }

    case "P256":
      try {
        const { p256 } = await import("@noble/curves/nist.js")
        return {
          async sign(signKey, message) {
            return p256.sign(message, signKey, { prehash: true, format: "der", lowS: false })
          },
          async verify(publicKey, message, signature) {
            return p256.verify(signature, message, publicKey, { prehash: true, format: "der", lowS: false })
          },
          async keygen() {
            const signKey = p256.utils.randomSecretKey()
            return { signKey, publicKey: p256.getPublicKey(signKey) }
          },
        }
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@noble/curves' is not installed. Please install it to use this feature.",
        )
      }
    case "P384":
      try {
        const { p384 } = await import("@noble/curves/nist.js")
        return {
          async sign(signKey, message) {
            return p384.sign(message, signKey, { prehash: true, format: "der", lowS: false })
          },
          async verify(publicKey, message, signature) {
            return p384.verify(signature, message, publicKey, { prehash: true, format: "der", lowS: false })
          },
          async keygen() {
            const signKey = p384.utils.randomSecretKey()
            return { signKey, publicKey: p384.getPublicKey(signKey) }
          },
        }
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@noble/curves' is not installed. Please install it to use this feature.",
        )
      }
    case "P521":
      try {
        const { p521 } = await import("@noble/curves/nist.js")
        return {
          async sign(signKey, message) {
            return p521.sign(message, signKey, { prehash: true, format: "der", lowS: false })
          },
          async verify(publicKey, message, signature) {
            return p521.verify(signature, message, publicKey, { prehash: true, format: "der", lowS: false })
          },
          async keygen() {
            const signKey = p521.utils.randomSecretKey()
            return { signKey, publicKey: p521.getPublicKey(signKey) }
          },
        }
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@noble/curves' is not installed. Please install it to use this feature.",
        )
      }
    case "ML-DSA-87":
      try {
        const { ml_dsa87 } = await import("@noble/post-quantum/ml-dsa.js")
        return {
          async sign(signKey, message) {
            return ml_dsa87.sign(message, signKey)
          },
          async verify(publicKey, message, signature) {
            return ml_dsa87.verify(signature, message, publicKey)
          },
          async keygen() {
            const keys = ml_dsa87.keygen(crypto.getRandomValues(new Uint8Array(32)))
            return { signKey: keys.secretKey, publicKey: keys.publicKey }
          },
        }
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@noble/post-quantum' is not installed. Please install it to use this feature.",
        )
      }
  }
}
