import { CiphersuiteImpl } from "./crypto/ciphersuite.js"

/** @public */
export interface SignatureKeyPair {
  signKey: Uint8Array
  publicKey: Uint8Array
}

/** @public */
export function generateSignatureKeyPair(cipherSuite: CiphersuiteImpl): Promise<SignatureKeyPair> {
  return cipherSuite.signature.keygen()
}
