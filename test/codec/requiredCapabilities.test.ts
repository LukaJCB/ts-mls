import {
  encodeRequiredCapabilities,
  decodeRequiredCapabilities,
  RequiredCapabilities,
} from "../../src/requiredCapabilities"
import { createRoundtripTest } from "./roundtrip"

describe("RequiredCapabilities roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeRequiredCapabilities, decodeRequiredCapabilities)

  it("roundtrips empty arrays", () => {
    const rc: RequiredCapabilities = {
      extensionTypes: [],
      proposalTypes: [],
      credentialTypes: [],
    }
    roundtrip(rc)
  })

  it("roundtrips non-empty arrays", () => {
    const rc: RequiredCapabilities = {
      extensionTypes: ["application_id", "ratchet_tree"],
      proposalTypes: ["add", "remove", "psk"],
      credentialTypes: ["basic", "x509"],
    }
    roundtrip(rc)
  })

  it("roundtrips single-element arrays", () => {
    const rc: RequiredCapabilities = {
      extensionTypes: ["external_pub"],
      proposalTypes: ["external_init"],
      credentialTypes: ["basic"],
    }
    roundtrip(rc)
  })
})
