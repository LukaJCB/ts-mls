import {
  defaultCredentialTypes,
  decodeCredentialType,
  decodeDefaultCredentialType,
  encodeCredentialType,
  encodeDefaultCredentialType,
  DefaultCredentialTypeName,
} from "../../src/credentialType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("CredentialType roundtrip", () => {
  const roundtripValue = createRoundtripTest(encodeCredentialType, decodeCredentialType)
  const roundtripName = createRoundtripTest(encodeDefaultCredentialType, decodeDefaultCredentialType)

  test("roundtrips basic", () => {
    roundtripValue(defaultCredentialTypes.basic)
    roundtripName("basic" as DefaultCredentialTypeName)
  })

  test("roundtrips x509", () => {
    roundtripValue(defaultCredentialTypes.x509)
    roundtripName("x509" as DefaultCredentialTypeName)
  })
})
