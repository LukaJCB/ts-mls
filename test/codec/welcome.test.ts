import { encodeWelcome, decodeWelcome } from "../../src/welcome.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("Welcome roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeWelcome, decodeWelcome)

  test("roundtrips minimal", () => {
    roundtrip({
      cipherSuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      secrets: [],
      encryptedGroupInfo: new Uint8Array([1]),
    })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({
      cipherSuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      secrets: [
        {
          newMember: new Uint8Array([2, 3]),
          encryptedGroupSecrets: { kemOutput: new Uint8Array([4]), ciphertext: new Uint8Array([5, 6]) },
        },
      ],
      encryptedGroupInfo: new Uint8Array([7, 8, 9]),
    })
  })
})
