import { CiphersuiteImpl, CiphersuiteName, ciphersuites } from "./ciphersuite.js"
import { CryptoProvider } from "./provider.js"
import { defaultCryptoProvider } from "./implementation/default/provider.js"

/** @public */
export async function getCiphersuiteImpl(
  cs: CiphersuiteName,
  provider: CryptoProvider = defaultCryptoProvider,
): Promise<CiphersuiteImpl> {
  return provider.getCiphersuiteImpl(ciphersuites[cs])
}
