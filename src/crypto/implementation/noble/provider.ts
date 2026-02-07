import { CiphersuiteImpl, ciphersuiteValues, isDefaultCiphersuiteId } from "../../ciphersuite.js"
import { makeHashImpl } from "./makeHashImpl.js"
import { DependencyError } from "../../../mlsError.js"
import { CryptoProvider } from "../../provider.js"
import { defaultRng } from "../default/rng.js"
import { makeNobleSignatureImpl } from "../default/makeNobleSignatureImpl.js"
import { makeKdf, makeKdfImpl } from "../default/makeKdfImpl.js"
import { makeHpke } from "../default/makeHpke.js"

/** @public */
export const nobleCryptoProvider: CryptoProvider = {
  async getCiphersuiteImpl(id: number): Promise<CiphersuiteImpl> {
    if (isDefaultCiphersuiteId(id)) {
      const cs = ciphersuiteValues[id]
      return {
        kdf: makeKdfImpl(makeKdf(cs.hpke.kdf)),
        hash: makeHashImpl(cs.hash),
        signature: await makeNobleSignatureImpl(cs.signature),
        hpke: await makeHpke(cs.hpke),
        rng: defaultRng,
        id: id,
      }
    } else {
      throw new DependencyError(`Unrecognized ciphersuite: ${id}`)
    }
  },
}
