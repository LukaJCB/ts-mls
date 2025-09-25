import { encodeEncryptedGroupSecrets, decodeEncryptedGroupSecrets } from "../../src/welcome.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("EncryptedGroupSecrets roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeEncryptedGroupSecrets, decodeEncryptedGroupSecrets)

  test("roundtrips minimal", () => {
    roundtrip({
      newMember: new Uint8Array([1]),
      encryptedGroupSecrets: { kemOutput: new Uint8Array([2]), ciphertext: new Uint8Array([3]) },
    })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({
      newMember: new Uint8Array([4, 5, 6]),
      encryptedGroupSecrets: { kemOutput: new Uint8Array([7, 8]), ciphertext: new Uint8Array([9, 10, 11]) },
    })
  })
})
