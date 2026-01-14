import { hpkeCiphertextEncoder, hpkeCiphertextDecoder, HPKECiphertext } from "../../src/hpkeCiphertext.js"
import { createRoundtripTest } from "./roundtrip.js"

const dummy: HPKECiphertext = {
  kemOutput: new Uint8Array([1, 2, 3]),
  ciphertext: new Uint8Array([4, 5, 6]),
}

describe("HPKECiphertext roundtrip", () => {
  const roundtrip = createRoundtripTest(hpkeCiphertextEncoder, hpkeCiphertextDecoder)

  test("roundtrips", () => {
    roundtrip(dummy)
  })
})
