import { encodeHpkeCiphertext, decodeHpkeCiphertext, HPKECiphertext } from "../../src/hpkeCiphertext"
import { createRoundtripTest } from "./roundtrip"

const dummy: HPKECiphertext = {
  kemOutput: new Uint8Array([1, 2, 3]),
  ciphertext: new Uint8Array([4, 5, 6]),
}

describe("HPKECiphertext roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeHpkeCiphertext, decodeHpkeCiphertext)

  test("roundtrips", () => {
    roundtrip(dummy)
  })
})
