import { Signature, SignatureAlgorithm } from "./signature.js"
import { Hash, HashAlgorithm } from "./hash.js"
import { Kdf } from "./kdf.js"
import { Hpke, HpkeAlgorithm } from "./hpke.js"
import { Encoder } from "../codec/tlsEncoder.js"
import { uint16Decoder, uint16Encoder } from "../codec/number.js"
import { Decoder } from "../codec/tlsDecoder.js"
import { Rng } from "./rng.js"

/** @public */
export interface CiphersuiteImpl {
  hash: Hash
  hpke: Hpke
  signature: Signature
  kdf: Kdf
  rng: Rng
  id: CiphersuiteId
}

/** @public */
export const ciphersuites = {
  MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519: 1,
  MLS_128_DHKEMP256_AES128GCM_SHA256_P256: 2,
  MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519: 3,
  MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448: 4,
  MLS_256_DHKEMP521_AES256GCM_SHA512_P521: 5,
  MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448: 6,
  MLS_256_DHKEMP384_AES256GCM_SHA384_P384: 7,
  MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519: 77,
  MLS_128_MLKEM512_CHACHA20POLY1305_SHA256_Ed25519: 78,
  MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519: 79,
  MLS_256_MLKEM768_CHACHA20POLY1305_SHA384_Ed25519: 80,
  MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519: 81,
  MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_Ed25519: 82,
  MLS_256_XWING_AES256GCM_SHA512_Ed25519: 83,
  MLS_256_XWING_CHACHA20POLY1305_SHA512_Ed25519: 84,
  MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87: 85,
  MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87: 86,
  MLS_256_XWING_AES256GCM_SHA512_MLDSA87: 87,
  MLS_256_XWING_CHACHA20POLY1305_SHA512_MLDSA87: 88,
} as const

/** @public */
export type CiphersuiteName = keyof typeof ciphersuites
/** @public */
export type CiphersuiteId = (typeof ciphersuites)[CiphersuiteName]

export function isDefaultCiphersuiteId(id: number): id is CiphersuiteId {
  return ciphersuiteValues[id as CiphersuiteId] ? true : false
}

export const ciphersuiteEncoder: Encoder<CiphersuiteId> = uint16Encoder

export const ciphersuiteDecoder: Decoder<CiphersuiteId> = (b, offset) => {
  const decoded = uint16Decoder(b, offset)
  return decoded === undefined ? undefined : [decoded[0] as CiphersuiteId, decoded[1]]
}

export function getCiphersuiteFromId(id: CiphersuiteId): Ciphersuite {
  return ciphersuiteValues[id]
}

/** @public */
export function getCiphersuiteFromName(name: CiphersuiteName): Ciphersuite {
  return ciphersuiteValues[ciphersuites[name]]
}

export const ciphersuiteValues: Record<CiphersuiteId, Ciphersuite> = {
  1: {
    hash: "SHA-256",
    hpke: {
      kem: "DHKEM-X25519-HKDF-SHA256",
      aead: "AES128GCM",
      kdf: "HKDF-SHA256",
    },
    signature: "Ed25519",
    id: 1,
  },
  2: {
    hash: "SHA-256",
    hpke: {
      kem: "DHKEM-P256-HKDF-SHA256",
      aead: "AES128GCM",
      kdf: "HKDF-SHA256",
    },
    signature: "P256",
    id: 2,
  },
  3: {
    hash: "SHA-256",
    hpke: {
      kem: "DHKEM-X25519-HKDF-SHA256",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA256",
    },
    signature: "Ed25519",
    id: 3,
  },
  4: {
    hash: "SHA-512",
    hpke: {
      kem: "DHKEM-X448-HKDF-SHA512",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed448",
    id: 4,
  },
  5: {
    hash: "SHA-512",
    hpke: {
      kem: "DHKEM-P521-HKDF-SHA512",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "P521",
    id: 5,
  },
  6: {
    hash: "SHA-512",
    hpke: {
      kem: "DHKEM-X448-HKDF-SHA512",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed448",
    id: 6,
  },
  7: {
    hash: "SHA-384",
    hpke: {
      kem: "DHKEM-P384-HKDF-SHA384",
      aead: "AES256GCM",
      kdf: "HKDF-SHA384",
    },
    signature: "P384",
    id: 7,
  },

  77: {
    hash: "SHA-256",
    hpke: {
      kem: "ML-KEM-512",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    id: 77,
  },
  78: {
    hash: "SHA-256",
    hpke: {
      kem: "ML-KEM-512",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    id: 78,
  },
  79: {
    hash: "SHA-384",
    hpke: {
      kem: "ML-KEM-768",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    id: 79,
  },
  80: {
    hash: "SHA-384",
    hpke: {
      kem: "ML-KEM-768",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    id: 80,
  },
  81: {
    hash: "SHA-512",
    hpke: {
      kem: "ML-KEM-1024",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    id: 81,
  },
  82: {
    hash: "SHA-512",
    hpke: {
      kem: "ML-KEM-1024",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    id: 82,
  },
  83: {
    hash: "SHA-512",
    hpke: {
      kem: "X-Wing",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    id: 83,
  },
  84: {
    hash: "SHA-512",
    hpke: {
      kem: "X-Wing",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    id: 84,
  },
  85: {
    hash: "SHA-512",
    hpke: {
      kem: "ML-KEM-1024",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "ML-DSA-87",
    id: 85,
  },
  86: {
    hash: "SHA-512",
    hpke: {
      kem: "ML-KEM-1024",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "ML-DSA-87",
    id: 86,
  },
  87: {
    hash: "SHA-512",
    hpke: {
      kem: "X-Wing",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "ML-DSA-87",
    id: 87,
  },
  88: {
    hash: "SHA-512",
    hpke: {
      kem: "X-Wing",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "ML-DSA-87",
    id: 88,
  },
} as const

/** @public */
export type Ciphersuite = {
  hash: HashAlgorithm
  hpke: HpkeAlgorithm
  signature: SignatureAlgorithm
  id: number
}
