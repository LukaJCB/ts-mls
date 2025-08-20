import { Ciphersuite, CiphersuiteImpl } from "./ciphersuite"

export interface CryptoProvider {
  getCiphersuiteImpl(cs: Ciphersuite): Promise<CiphersuiteImpl>
}
