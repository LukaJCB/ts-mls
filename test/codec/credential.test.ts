import { encodeCredential, decodeCredential, Credential } from "../../src/credential.js"
import { createRoundtripTest } from "./roundtrip.js"

const minimal: Credential = { credentialType: "basic", identity: new Uint8Array([1, 2, 3]) }

const nontrivial: Credential = {
  credentialType: "x509",
  certificates: [new Uint8Array([4, 5, 6]), new Uint8Array([7, 8, 9, 10])],
}

describe("Credential roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeCredential, decodeCredential)

  test("roundtrips minimal", () => {
    roundtrip(minimal)
  })

  test("roundtrips nontrivial", () => {
    roundtrip(nontrivial)
  })
})
