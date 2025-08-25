import { Ciphersuite, CiphersuiteImpl } from "../../ciphersuite"

import { makeHashImpl } from "./makeHashImpl"
import { makeNobleSignatureImpl } from "./makeNobleSignatureImpl"
import { makeHpke } from "./makeHpke"
import { makeKdfImpl, makeKdf } from "./makeKdfImpl"
import { rng } from "./rng"

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
