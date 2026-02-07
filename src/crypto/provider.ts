import { CiphersuiteImpl } from "./ciphersuite.js"

/** @public */
export interface CryptoProvider {
  getCiphersuiteImpl(id: number): Promise<CiphersuiteImpl>
}
