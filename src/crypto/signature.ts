import { encodeVarLenData } from "../codec/variableLength"
import { concatUint8Arrays } from "../util/byteArray"

export interface Signature {
  sign(signKey: Uint8Array, message: Uint8Array): Promise<Uint8Array>
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>
  keygen(): Promise<{ publicKey: Uint8Array; signKey: Uint8Array }>
}

export type SignatureAlgorithm = "Ed25519" | "Ed448" | "P256" | "P384" | "P521" | "ML-DSA-87"

export async function signWithLabel(
  signKey: Uint8Array,
  label: string,
  content: Uint8Array,
  s: Signature,
): Promise<Uint8Array> {
  return s.sign(
    signKey,
    concatUint8Arrays(encodeVarLenData(new TextEncoder().encode(`MLS 1.0 ${label}`)), encodeVarLenData(content)),
  )
}

export async function verifyWithLabel(
  publicKey: Uint8Array,
  label: string,
  content: Uint8Array,
  signature: Uint8Array,
  s: Signature,
): Promise<boolean> {
  return s.verify(
    publicKey,
    concatUint8Arrays(encodeVarLenData(new TextEncoder().encode(`MLS 1.0 ${label}`)), encodeVarLenData(content)),
    signature,
  )
}
