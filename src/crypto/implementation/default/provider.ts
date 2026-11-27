import { CiphersuiteImpl, ciphersuiteValues, isDefaultCiphersuiteId } from "../../ciphersuite.js"

import { makeHashImpl } from "./makeHashImpl.js"
import { makeHpke } from "./makeHpke.js"
import { makeKdf } from "./makeKdfImpl.js"
import { makeKdfImpl } from "./makeKdfImpl.js"
import { defaultRng } from "./rng.js"
import { makeNobleSignatureImpl } from "./makeNobleSignatureImpl.js"
import { DependencyError } from "../../../mlsError.js"
import { CryptoProvider } from "../../provider.js"
import { runCryptoOperation, wrapCiphersuiteErrors } from "../../errors.js"

/** @public */
export const defaultCryptoProvider: CryptoProvider = {
  getCiphersuiteImpl(id: number): Promise<CiphersuiteImpl> {
    return runCryptoOperation("Ciphersuite initialization", async () => {
      if (isDefaultCiphersuiteId(id)) {
        const cs = ciphersuiteValues[id]
        const sc = crypto.subtle
        return wrapCiphersuiteErrors({
          kdf: makeKdfImpl(makeKdf(cs.hpke.kdf)),
          hash: makeHashImpl(sc, cs.hash),
          signature: await makeNobleSignatureImpl(cs.signature),
          hpke: await makeHpke(cs.hpke),
          rng: defaultRng,
          id: id,
        })
      } else {
        throw new DependencyError(`Unrecognized ciphersuite: ${id}`)
      }
    })
  },
}
