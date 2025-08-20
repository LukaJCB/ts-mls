import { Ciphersuite, CiphersuiteImpl } from "../../ciphersuite"

import { makeHashImpl } from "./makeHashImpl"
import { makeHpke } from "./makeHpke"
import { makeKdf } from "./makeKdfImpl"
import { makeKdfImpl } from "./makeKdfImpl"
import { webCryptoRng } from "./webCryptoRng"
import { makeNobleSignatureImpl } from "./makeNobleSignatureImpl"

export const defaultCryptoProvider = {
  async getCiphersuiteImpl(cs: Ciphersuite): Promise<CiphersuiteImpl> {
    const sc = crypto.subtle
    return {
      kdf: makeKdfImpl(makeKdf(cs.hpke.kdf)),
      hash: makeHashImpl(sc, cs.hash),
      signature: await makeNobleSignatureImpl(cs.signature),
      hpke: await makeHpke(cs.hpke),
      rng: webCryptoRng,
      name: cs.name,
    }
  },
}
