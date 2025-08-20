import { Ciphersuite, CiphersuiteImpl } from "./ciphersuite"
import { CryptoProvider } from "./provider"
import { defaultCryptoProvider } from "./implementation/default/provider"

export async function getCiphersuiteImpl(
  cs: Ciphersuite,
  provider: CryptoProvider = defaultCryptoProvider,
): Promise<CiphersuiteImpl> {
  return provider.getCiphersuiteImpl(cs)
}
