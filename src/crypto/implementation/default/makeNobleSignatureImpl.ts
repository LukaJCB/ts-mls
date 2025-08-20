import { DependencyError } from "../../../mlsError"
import { SignatureAlgorithm, Signature } from "../../signature"

export async function makeNobleSignatureImpl(alg: SignatureAlgorithm): Promise<Signature> {
  switch (alg) {
    case "Ed25519":
      try {
        const { ed25519 } = await import("@noble/curves/ed25519")
        return {
          async sign(signKey, message) {
            return ed25519.sign(message, signKey)
          },
          async verify(publicKey, message, signature) {
            return ed25519.verify(signature, message, publicKey)
          },
          async keygen() {
            const signKey = ed25519.utils.randomPrivateKey()
            return { signKey, publicKey: ed25519.getPublicKey(signKey) }
          },
        }
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@noble/curves' is not installed. Please install it to use this feature.",
        )
      }

    case "Ed448":
      try {
        const { ed448 } = await import("@noble/curves/ed448")
        return {
          async sign(signKey, message) {
            return ed448.sign(message, signKey)
          },
          async verify(publicKey, message, signature) {
            return ed448.verify(signature, message, publicKey)
          },
          async keygen() {
            const signKey = ed448.utils.randomPrivateKey()
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
        const { p256 } = await import("@noble/curves/nist")
        return {
          async sign(signKey, message) {
            return p256.sign(message, signKey, { prehash: true }).toCompactRawBytes()
          },
          async verify(publicKey, message, signature) {
            return p256.verify(signature, message, publicKey, { prehash: true })
          },
          async keygen() {
            const signKey = p256.utils.randomPrivateKey()
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
        const { p384 } = await import("@noble/curves/nist")
        return {
          async sign(signKey, message) {
            return p384.sign(message, signKey, { prehash: true }).toCompactRawBytes()
          },
          async verify(publicKey, message, signature) {
            return p384.verify(signature, message, publicKey, { prehash: true })
          },
          async keygen() {
            const signKey = p384.utils.randomPrivateKey()
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
        const { p521 } = await import("@noble/curves/nist")
        return {
          async sign(signKey, message) {
            return p521.sign(message, signKey, { prehash: true }).toCompactRawBytes()
          },
          async verify(publicKey, message, signature) {
            return p521.verify(signature, message, publicKey, { prehash: true })
          },
          async keygen() {
            const signKey = p521.utils.randomPrivateKey()
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
        const { ml_dsa87 } = await import("@noble/post-quantum/ml-dsa")
        return {
          async sign(signKey, message) {
            return ml_dsa87.sign(signKey, message)
          },
          async verify(publicKey, message, signature) {
            return ml_dsa87.verify(publicKey, message, signature)
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
