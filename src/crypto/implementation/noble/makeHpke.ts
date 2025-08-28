import { CipherSuite } from "@hpke/core"
import { Hpke, HpkeAlgorithm } from "../../hpke"
import { makeGenericHpke } from "../hpke"
import { makeAead } from "./makeAead.js"
import { makeKdf } from "./makeKdfImpl.js"
import { makeDhKem } from "./makeDhKem.js"

export async function makeHpke(hpkealg: HpkeAlgorithm): Promise<Hpke> {
  const [aead, aeadInterface] = await makeAead(hpkealg.aead)
  const cs = new CipherSuite({
    kem: await makeDhKem(hpkealg.kem),
    kdf: makeKdf(hpkealg.kdf),
    aead: aeadInterface,
  })

  return makeGenericHpke(hpkealg, aead, cs)
}
