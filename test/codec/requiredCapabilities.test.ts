import {
  encodeRequiredCapabilities,
  decodeRequiredCapabilities,
  RequiredCapabilities,
} from "../../src/requiredCapabilities.js"
import { credentialTypes } from "../../src/credentialType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("RequiredCapabilities roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeRequiredCapabilities, decodeRequiredCapabilities)

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
      credentialTypes: [credentialTypes.basic, credentialTypes.x509],
    }
    roundtrip(rc)
  })

  test("roundtrips single-element arrays", () => {
    const rc: RequiredCapabilities = {
      extensionTypes: [8],
      proposalTypes: [9],
      credentialTypes: [credentialTypes.basic],
    }
    roundtrip(rc)
  })
})
