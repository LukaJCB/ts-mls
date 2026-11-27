import {
  CiphersuiteImpl,
  CryptoError,
  CryptoVerificationError,
  defaultCryptoProvider,
  DependencyError,
  getCiphersuiteImpl,
  MlsError,
  nobleCryptoProvider,
  UsageError,
  ValidationError,
} from "../../src/index.js"
import { PrivateKey, PublicKey } from "../../src/crypto/hpke.js"
import { OpenError } from "@hpke/core"
import { wrapCiphersuiteErrors } from "../../src/crypto/errors.js"

const suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
const data = new Uint8Array([1, 2, 3])
let base: CiphersuiteImpl
let privateKey: PrivateKey
let publicKey: PublicKey

beforeAll(async () => {
  base = await getCiphersuiteImpl(suite)
  ;({ privateKey, publicKey } = await base.hpke.generateKeyPair())
})

async function cryptoFailure(operation: Promise<unknown>): Promise<CryptoError> {
  try {
    await operation
  } catch (error) {
    expect(error).toBeInstanceOf(CryptoError)
    return error as CryptoError
  }
  throw new Error("Expected a rejected crypto operation")
}

// Every asynchronous operation exposed by CiphersuiteImpl, including operations
// that previously allowed raw provider exceptions to escape.
const operations: [string, (impl: CiphersuiteImpl) => Promise<unknown>][] = [
  ["HPKE open", (cs) => cs.hpke.open(privateKey, data, data, data)],
  ["HPKE seal", (cs) => cs.hpke.seal(publicKey, data, data)],
  ["HPKE importSecret", (cs) => cs.hpke.importSecret(privateKey, data, data, 16, data)],
  ["HPKE exportSecret", (cs) => cs.hpke.exportSecret(publicKey, data, 16, data)],
  ["HPKE importPrivateKey", (cs) => cs.hpke.importPrivateKey(data)],
  ["HPKE importPublicKey", (cs) => cs.hpke.importPublicKey(data)],
  ["HPKE exportPrivateKey", (cs) => cs.hpke.exportPrivateKey(privateKey)],
  ["HPKE exportPublicKey", (cs) => cs.hpke.exportPublicKey(publicKey)],
  ["AEAD encrypt", (cs) => cs.hpke.encryptAead(data, data, data, data)],
  ["AEAD decrypt", (cs) => cs.hpke.decryptAead(data, data, data, data)],
  ["HPKE deriveKeyPair", (cs) => cs.hpke.deriveKeyPair(data)],
  ["HPKE generateKeyPair", (cs) => cs.hpke.generateKeyPair()],
  ["Hash digest", (cs) => cs.hash.digest(data)],
  ["MAC generation", (cs) => cs.hash.mac(data, data)],
  ["MAC verification", (cs) => cs.hash.verifyMac(data, data, data)],
  ["KDF extract", (cs) => cs.kdf.extract(data, data)],
  ["KDF expand", (cs) => cs.kdf.expand(data, data, 16)],
  ["Signature generation", (cs) => cs.signature.sign(data, data)],
  ["Signature verification", (cs) => cs.signature.verify(data, data, data)],
  ["Signature key generation", (cs) => cs.signature.keygen()],
]

function failingImplementation(cause: unknown, synchronous: boolean): CiphersuiteImpl {
  const fail = synchronous
    ? () => {
        throw cause
      }
    : async () => {
        throw cause
      }
  return {
    id: base.id,
    hpke: {
      open: fail,
      seal: fail,
      importSecret: fail,
      exportSecret: fail,
      importPrivateKey: fail,
      importPublicKey: fail,
      exportPrivateKey: fail,
      exportPublicKey: fail,
      encryptAead: fail,
      decryptAead: fail,
      deriveKeyPair: fail,
      generateKeyPair: fail,
      keyLength: base.hpke.keyLength,
      nonceLength: base.hpke.nonceLength,
    },
    hash: { digest: fail, mac: fail, verifyMac: fail },
    kdf: { extract: fail, expand: fail, size: base.kdf.size },
    signature: { sign: fail, verify: fail, keygen: fail },
    rng: {
      randomBytes() {
        throw cause
      },
    },
  }
}

describe.each([false, true])("provider throws synchronously: %s", (synchronous) => {
  test.each(operations)("wraps %s with operation context and the original cause", async (operation, invoke) => {
    const cause = new Error("provider failure")
    const impl = wrapCiphersuiteErrors(failingImplementation(cause, synchronous))
    const error = await cryptoFailure(invoke(impl))
    expect(error).toMatchObject({
      name: "CryptoError",
      message: `${operation} failed`,
      cause,
    })
    expect(error.cause).toBe(cause)
  })
})

test.each([
  new MlsError("MLS error"),
  new CryptoError("already wrapped", { cause: new Error("original") }),
  new CryptoVerificationError("verification failed"),
  new DependencyError("missing dependency"),
  new UsageError("usage error"),
  new ValidationError("validation error"),
])("preserves an existing $name without wrapping it again", async (original) => {
  const impl = wrapCiphersuiteErrors(failingImplementation(original, false))
  for (const [, invoke] of operations) await expect(invoke(impl)).rejects.toBe(original)
  expect(() => impl.rng.randomBytes(1)).toThrow(original)
})

test("keeps RNG failures synchronous and preserves their cause", async () => {
  const cause = new Error("entropy unavailable")
  const impl = wrapCiphersuiteErrors(failingImplementation(cause, false))
  try {
    impl.rng.randomBytes(1)
    throw new Error("Expected RNG to throw")
  } catch (error) {
    expect(error).toBeInstanceOf(CryptoError)
    expect((error as CryptoError).cause).toBe(cause)
    expect((error as CryptoError).message).toBe("Random byte generation failed")
  }
})

test.each([new Error("initialization failed"), "non-Error rejection"])(
  "preserves custom provider initialization errors: %s",
  async (cause) => {
    await expect(
      getCiphersuiteImpl(suite, {
        getCiphersuiteImpl() {
          if (cause instanceof Error) throw cause
          // Third-party providers can reject with non-Error values too.
          // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
          return Promise.reject(cause)
        },
      }),
    ).rejects.toBe(cause)
  },
)

test("preserves DependencyError from provider initialization", async () => {
  const original = new DependencyError("missing provider", { cause: new Error("module not found") })
  await expect(
    getCiphersuiteImpl(suite, {
      async getCiphersuiteImpl() {
        throw original
      },
    }),
  ).rejects.toBe(original)
})

test("preserves verification results and provider method receivers", async () => {
  const hash = {
    digest: (input: Uint8Array) => base.hash.digest(input),
    mac: async () => data,
    async verifyMac() {
      return (await this.mac()).length === 0
    },
  }
  const impl = wrapCiphersuiteErrors({ ...base, hash, signature: { ...base.signature, verify: async () => false } })
  expect(await impl.hash.mac(data, data)).toBe(data)
  await expect(impl.hash.verifyMac(data, data, data)).resolves.toBe(false)
  await expect(impl.signature.verify(data, data, data)).resolves.toBe(false)
})

test("getCiphersuiteImpl returns custom implementations and their operation errors unchanged", async () => {
  const original = new Error("custom provider failure")
  const provided = failingImplementation(original, false)
  const impl = await getCiphersuiteImpl(suite, {
    async getCiphersuiteImpl() {
      return provided
    },
  })
  expect(impl).toBe(provided)
  for (const [, invoke] of operations) await expect(invoke(impl)).rejects.toBe(original)
  expect(() => impl.rng.randomBytes(1)).toThrow(original)
})

test.each([defaultCryptoProvider, nobleCryptoProvider])(
  "built-in provider wraps errors when used directly (%#)",
  async (provider) => {
    const impl = await provider.getCiphersuiteImpl(1)
    const encryptError = await cryptoFailure(impl.hpke.encryptAead(data, data, data, data))
    expect(encryptError.message).toBe("AEAD encrypt failed")
    expect(encryptError.cause).toBeInstanceOf(Error)
    const verifyError = await cryptoFailure(impl.signature.verify(new Uint8Array(), data, data))
    expect(verifyError.message).toBe("Signature verification failed")
    expect(verifyError.cause).toBeInstanceOf(Error)

    const keys = await impl.hpke.generateKeyPair()
    const { enc, ct } = await impl.hpke.seal(keys.publicKey, data, data)
    ct[0]! ^= 1
    const openError = await cryptoFailure(impl.hpke.open(keys.privateKey, enc, ct, data))
    expect(openError.message).toBe("HPKE open failed")
    expect(openError.cause).toBeInstanceOf(OpenError)

    const signingKeys = await impl.signature.keygen()
    const signature = await impl.signature.sign(signingKeys.signKey, data)
    await expect(impl.signature.verify(signingKeys.publicKey, new Uint8Array([4]), signature)).resolves.toBe(false)
  },
)
