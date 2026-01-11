import { encodeExternalSender, decodeExternalSender, ExternalSender } from "../../src/externalSender.js"
import { defaultCredentialTypes } from "../../src/credentialType.js"
import { createRoundtripTest } from "./roundtrip.js"

const basic: ExternalSender = {
  signaturePublicKey: new Uint8Array([1, 2, 3]),
  credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([4, 5, 6]) },
}

const x509: ExternalSender = {
  signaturePublicKey: new Uint8Array([7, 8, 9, 10, 11]),
  credential: {
    credentialType: defaultCredentialTypes.x509,
    certificates: [new Uint8Array([12, 13]), new Uint8Array([14, 15, 16])],
  },
}

describe("ExternalSender roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeExternalSender, decodeExternalSender)

  test("roundtrips basic", () => {
    roundtrip(basic)
  })

  test("roundtrips x509", () => {
    roundtrip(x509)
  })
})
