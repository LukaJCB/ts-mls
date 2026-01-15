import {
  requiredCapabilitiesEncoder,
  requiredCapabilitiesDecoder,
  RequiredCapabilities,
} from "../../src/requiredCapabilities.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("RequiredCapabilities roundtrip", () => {
  const roundtrip = createRoundtripTest(requiredCapabilitiesEncoder, requiredCapabilitiesDecoder)

  test("roundtrips empty arrays", () => {
    const rc: RequiredCapabilities = {
      extensionTypes: [],
      proposalTypes: [],
      credentialTypes: [],
    }
    roundtrip(rc)
  })

  test("roundtrips non-empty arrays", () => {
    const rc: RequiredCapabilities = {
      extensionTypes: [7, 8],
      proposalTypes: [9, 10, 11],
      credentialTypes: [defaultCredentialTypes.basic, defaultCredentialTypes.x509],
    }
    roundtrip(rc)
  })

  test("roundtrips single-element arrays", () => {
    const rc: RequiredCapabilities = {
      extensionTypes: [8],
      proposalTypes: [9],
      credentialTypes: [defaultCredentialTypes.basic],
    }
    roundtrip(rc)
  })
})
