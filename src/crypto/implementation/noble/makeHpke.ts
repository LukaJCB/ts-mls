import { CipherSuite } from "@hpke/core"
import { Hpke, HpkeAlgorithm, makeGenericHpke } from "../../hpke"
import { makeAead } from "./makeAead"
import { makeKdf } from "./makeKdfImpl"
import { makeDhKem } from "./makeDhKem"

export async function makeHpke(hpkealg: HpkeAlgorithm): Promise<Hpke> {
  const [aead, aeadInterface] = await makeAead(hpkealg.aead)
  const cs = new CipherSuite({
    kem: await makeDhKem(hpkealg.kem),
    kdf: makeKdf(hpkealg.kdf),
    aead: aeadInterface,
  })

  return makeGenericHpke(hpkealg, aead, cs)
}
