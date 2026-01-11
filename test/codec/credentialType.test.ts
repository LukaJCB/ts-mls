import {
  credentialTypes,
  decodeCredentialType,
  decodeCredentialTypeName,
  encodeCredentialType,
  encodeCredentialTypeName,
  CredentialTypeName,
} from "../../src/credentialType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("CredentialType roundtrip", () => {
  const roundtripValue = createRoundtripTest(encodeCredentialType, decodeCredentialType)
  const roundtripName = createRoundtripTest(encodeCredentialTypeName, decodeCredentialTypeName)

  test("roundtrips basic", () => {
    roundtripValue(credentialTypes.basic)
    roundtripName("basic" as CredentialTypeName)
  })

  test("roundtrips x509", () => {
    roundtripValue(credentialTypes.x509)
    roundtripName("x509" as CredentialTypeName)
  })
})
