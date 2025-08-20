import { Signature, SignatureAlgorithm } from "./signature"
import { Hash, HashAlgorithm } from "./hash"
import { Kdf } from "./kdf"
import { Hpke, HpkeAlgorithm } from "./hpke"
import { contramapEncoder, Encoder } from "../codec/tlsEncoder"
import { decodeUint16, encodeUint16 } from "../codec/number"
import { Decoder, mapDecoderOption } from "../codec/tlsDecoder"
import { openEnumNumberEncoder, openEnumNumberToKey, reverseMap } from "../util/enumHelpers"
import { Rng } from "./rng"

export interface CiphersuiteImpl {
  hash: Hash
  hpke: Hpke
  signature: Signature
  kdf: Kdf
  rng: Rng
  name: CiphersuiteName
}

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

export type CiphersuiteName = keyof typeof ciphersuites
export type CiphersuiteId = (typeof ciphersuites)[CiphersuiteName]

export const encodeCiphersuite: Encoder<CiphersuiteName> = contramapEncoder(
  encodeUint16,
  openEnumNumberEncoder(ciphersuites),
)

export const decodeCiphersuite: Decoder<CiphersuiteName> = mapDecoderOption(
  decodeUint16,
  openEnumNumberToKey(ciphersuites),
)

export function getCiphersuiteNameFromId(id: CiphersuiteId): CiphersuiteName {
  return reverseMap(ciphersuites)[id] as CiphersuiteName
}

export function getCiphersuiteFromId(id: CiphersuiteId): Ciphersuite {
  return ciphersuiteValues[id]
}

export function getCiphersuiteFromName(name: CiphersuiteName): Ciphersuite {
  return ciphersuiteValues[ciphersuites[name]]
}

const ciphersuiteValues: Record<CiphersuiteId, Ciphersuite> = {
  1: {
    hash: "SHA-256",
    hpke: {
      kem: "DHKEM-X25519-HKDF-SHA256",
      aead: "AES128GCM",
      kdf: "HKDF-SHA256",
    },
    signature: "Ed25519",
    name: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
  },
  2: {
    hash: "SHA-256",
    hpke: {
      kem: "DHKEM-P256-HKDF-SHA256",
      aead: "AES128GCM",
      kdf: "HKDF-SHA256",
    },
    signature: "P256",
    name: "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
  },
  3: {
    hash: "SHA-256",
    hpke: {
      kem: "DHKEM-X25519-HKDF-SHA256",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA256",
    },
    signature: "Ed25519",
    name: "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
  },
  4: {
    hash: "SHA-512",
    hpke: {
      kem: "DHKEM-X448-HKDF-SHA512",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed448",
    name: "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
  },
  5: {
    hash: "SHA-512",
    hpke: {
      kem: "DHKEM-P521-HKDF-SHA512",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "P521",
    name: "MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
  },
  6: {
    hash: "SHA-512",
    hpke: {
      kem: "DHKEM-X448-HKDF-SHA512",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed448",
    name: "MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448",
  },
  7: {
    hash: "SHA-384",
    hpke: {
      kem: "DHKEM-P384-HKDF-SHA384",
      aead: "AES256GCM",
      kdf: "HKDF-SHA384",
    },
    signature: "P384",
    name: "MLS_256_DHKEMP384_AES256GCM_SHA384_P384",
  },

  77: {
    hash: "SHA-256",
    hpke: {
      kem: "ML-KEM-512",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    name: "MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519",
  },
  78: {
    hash: "SHA-256",
    hpke: {
      kem: "ML-KEM-512",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    name: "MLS_128_MLKEM512_CHACHA20POLY1305_SHA256_Ed25519",
  },
  79: {
    hash: "SHA-384",
    hpke: {
      kem: "ML-KEM-768",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    name: "MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519",
  },
  80: {
    hash: "SHA-384",
    hpke: {
      kem: "ML-KEM-768",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    name: "MLS_256_MLKEM768_CHACHA20POLY1305_SHA384_Ed25519",
  },
  81: {
    hash: "SHA-512",
    hpke: {
      kem: "ML-KEM-1024",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    name: "MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519",
  },
  82: {
    hash: "SHA-512",
    hpke: {
      kem: "ML-KEM-1024",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    name: "MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_Ed25519",
  },
  83: {
    hash: "SHA-512",
    hpke: {
      kem: "X-Wing",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    name: "MLS_256_XWING_AES256GCM_SHA512_Ed25519",
  },
  84: {
    hash: "SHA-512",
    hpke: {
      kem: "X-Wing",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed25519",
    name: "MLS_256_XWING_CHACHA20POLY1305_SHA512_Ed25519",
  },
  85: {
    hash: "SHA-512",
    hpke: {
      kem: "ML-KEM-1024",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "ML-DSA-87",
    name: "MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87",
  },
  86: {
    hash: "SHA-512",
    hpke: {
      kem: "ML-KEM-1024",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "ML-DSA-87",
    name: "MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87",
  },
  87: {
    hash: "SHA-512",
    hpke: {
      kem: "X-Wing",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "ML-DSA-87",
    name: "MLS_256_XWING_AES256GCM_SHA512_MLDSA87",
  },
  88: {
    hash: "SHA-512",
    hpke: {
      kem: "X-Wing",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "ML-DSA-87",
    name: "MLS_256_XWING_CHACHA20POLY1305_SHA512_MLDSA87",
  },
} as const

export type Ciphersuite = {
  hash: HashAlgorithm
  hpke: HpkeAlgorithm
  signature: SignatureAlgorithm
  name: CiphersuiteName
}
