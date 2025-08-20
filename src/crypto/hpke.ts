import { AeadAlgorithm } from "./aead"
import { KdfAlgorithm } from "./kdf"
import { KemAlgorithm } from "./kem"
import { encodeVarLenData } from "../codec/variableLength"
import { concatUint8Arrays } from "../util/byteArray"

export type PublicKey = CryptoKey & { type: "public" }
export type SecretKey = CryptoKey & { type: "secret" }
export type PrivateKey = CryptoKey & { type: "private" }

export interface HpkeAlgorithm {
  kem: KemAlgorithm
  kdf: KdfAlgorithm
  aead: AeadAlgorithm
}

export function encryptWithLabel(
  publicKey: PublicKey,
  label: string,
  context: Uint8Array,
  plaintext: Uint8Array,
  hpke: Hpke,
): Promise<{ ct: Uint8Array; enc: Uint8Array }> {
  return hpke.seal(
    publicKey,
    plaintext,
    concatUint8Arrays(encodeVarLenData(new TextEncoder().encode(`MLS 1.0 ${label}`)), encodeVarLenData(context)),
    new Uint8Array(),
  )
}

export function decryptWithLabel(
  privateKey: PrivateKey,
  label: string,
  context: Uint8Array,
  kemOutput: Uint8Array,
  ciphertext: Uint8Array,
  hpke: Hpke,
): Promise<Uint8Array> {
  return hpke.open(
    privateKey,
    kemOutput,
    ciphertext,
    concatUint8Arrays(encodeVarLenData(new TextEncoder().encode(`MLS 1.0 ${label}`)), encodeVarLenData(context)),
  )
}

export interface Hpke {
  open(
    privateKey: PrivateKey,
    kemOutput: Uint8Array,
    ciphertext: Uint8Array,
    info: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array>
  seal(
    publicKey: PublicKey,
    plaintext: Uint8Array,
    info: Uint8Array,
    aad?: Uint8Array,
  ): Promise<{ ct: Uint8Array; enc: Uint8Array }>
  importPrivateKey(k: Uint8Array): Promise<PrivateKey>
  importPublicKey(k: Uint8Array): Promise<PublicKey>
  exportPublicKey(k: PublicKey): Promise<Uint8Array>
  exportPrivateKey(k: PrivateKey): Promise<Uint8Array>
  encryptAead(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array | undefined,
    plaintext: Uint8Array,
  ): Promise<Uint8Array>
  decryptAead(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array | undefined,
    ciphertext: Uint8Array,
  ): Promise<Uint8Array>
  exportSecret(
    publicKey: PublicKey,
    exporterContext: Uint8Array,
    length: number,
    info: Uint8Array,
  ): Promise<{ enc: Uint8Array; secret: Uint8Array }>
  importSecret(
    privateKey: PrivateKey,
    exporterContext: Uint8Array,
    kemOutput: Uint8Array,
    length: number,
    info: Uint8Array,
  ): Promise<Uint8Array>
  deriveKeyPair(ikm: Uint8Array): Promise<{ privateKey: PrivateKey; publicKey: PublicKey }>
  generateKeyPair(): Promise<{ privateKey: PrivateKey; publicKey: PublicKey }>
  keyLength: number
  nonceLength: number
}
