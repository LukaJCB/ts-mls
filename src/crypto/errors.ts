import { CryptoError, MlsError } from "../mlsError.js"
import { CiphersuiteImpl } from "./ciphersuite.js"
import { Hpke } from "./hpke.js"

function rethrowCryptoError(operation: string, cause: unknown): never {
  if (cause instanceof MlsError) throw cause
  throw new CryptoError(`${operation} failed`, { cause })
}

export async function runCryptoOperation<T>(operation: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run()
  } catch (cause) {
    rethrowCryptoError(operation, cause)
  }
}

function wrapHpkeErrors(hpke: Hpke): Hpke {
  return {
    open: (...args) => runCryptoOperation("HPKE open", () => hpke.open(...args)),
    seal: (...args) => runCryptoOperation("HPKE seal", () => hpke.seal(...args)),
    importSecret: (...args) => runCryptoOperation("HPKE importSecret", () => hpke.importSecret(...args)),
    exportSecret: (...args) => runCryptoOperation("HPKE exportSecret", () => hpke.exportSecret(...args)),
    importPrivateKey: (...args) => runCryptoOperation("HPKE importPrivateKey", () => hpke.importPrivateKey(...args)),
    importPublicKey: (...args) => runCryptoOperation("HPKE importPublicKey", () => hpke.importPublicKey(...args)),
    exportPrivateKey: (...args) => runCryptoOperation("HPKE exportPrivateKey", () => hpke.exportPrivateKey(...args)),
    exportPublicKey: (...args) => runCryptoOperation("HPKE exportPublicKey", () => hpke.exportPublicKey(...args)),
    encryptAead: (...args) => runCryptoOperation("AEAD encrypt", () => hpke.encryptAead(...args)),
    decryptAead: (...args) => runCryptoOperation("AEAD decrypt", () => hpke.decryptAead(...args)),
    deriveKeyPair: (...args) => runCryptoOperation("HPKE deriveKeyPair", () => hpke.deriveKeyPair(...args)),
    generateKeyPair: (...args) => runCryptoOperation("HPKE generateKeyPair", () => hpke.generateKeyPair(...args)),
    keyLength: hpke.keyLength,
    nonceLength: hpke.nonceLength,
  }
}

export function wrapCiphersuiteErrors(impl: CiphersuiteImpl): CiphersuiteImpl {
  return {
    id: impl.id,
    hpke: wrapHpkeErrors(impl.hpke),
    hash: {
      digest: (...args) => runCryptoOperation("Hash digest", () => impl.hash.digest(...args)),
      mac: (...args) => runCryptoOperation("MAC generation", () => impl.hash.mac(...args)),
      verifyMac: (...args) => runCryptoOperation("MAC verification", () => impl.hash.verifyMac(...args)),
    },
    kdf: {
      extract: (...args) => runCryptoOperation("KDF extract", () => impl.kdf.extract(...args)),
      expand: (...args) => runCryptoOperation("KDF expand", () => impl.kdf.expand(...args)),
      size: impl.kdf.size,
    },
    signature: {
      sign: (...args) => runCryptoOperation("Signature generation", () => impl.signature.sign(...args)),
      verify: (...args) => runCryptoOperation("Signature verification", () => impl.signature.verify(...args)),
      keygen: (...args) => runCryptoOperation("Signature key generation", () => impl.signature.keygen(...args)),
    },
    rng: {
      randomBytes: (length) => {
        try {
          return impl.rng.randomBytes(length)
        } catch (cause) {
          rethrowCryptoError("Random byte generation", cause)
        }
      },
    },
  }
}
