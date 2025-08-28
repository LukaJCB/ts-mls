import { Ciphersuite, CiphersuiteImpl } from "../../ciphersuite"

import { makeHashImpl } from "./makeHashImpl.js"
import { makeNobleSignatureImpl } from "./makeNobleSignatureImpl.js"
import { makeHpke } from "./makeHpke.js"
import { makeKdfImpl, makeKdf } from "./makeKdfImpl.js"
import { rng } from "./rng.js"

export const nobleCryptoProvider = {
  async getCiphersuiteImpl(cs: Ciphersuite): Promise<CiphersuiteImpl> {
    return {
      kdf: makeKdfImpl(makeKdf(cs.hpke.kdf)),
      hash: makeHashImpl(cs.hash),
      signature: await makeNobleSignatureImpl(cs.signature),
      hpke: await makeHpke(cs.hpke),
      rng: rng,
      name: cs.name,
    }
  },
}
