import { credentialEncoder, decodeCredential, Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { createRoundtripTest } from "./roundtrip.js"

const minimal: Credential = { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([1, 2, 3]) }

const nontrivial: Credential = {
  credentialType: defaultCredentialTypes.x509,
  certificates: [new Uint8Array([4, 5, 6]), new Uint8Array([7, 8, 9, 10])],
}

describe("Credential roundtrip", () => {
  const roundtrip = createRoundtripTest(credentialEncoder, decodeCredential)

  test("roundtrips minimal", () => {
    roundtrip(minimal)
  })

  test("roundtrips nontrivial", () => {
    roundtrip(nontrivial)
  })
})
