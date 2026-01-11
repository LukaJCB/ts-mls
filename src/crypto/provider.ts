import { Ciphersuite, CiphersuiteImpl } from "./ciphersuite.js"

/** @public */
export interface CryptoProvider {
  getCiphersuiteImpl(cs: Ciphersuite): Promise<CiphersuiteImpl>
}
