import { encodeCapabilities, decodeCapabilities, Capabilities } from "../../src/capabilities.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("Capabilities roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeCapabilities, decodeCapabilities)

  test("roundtrips minimal", () => {
    const c: Capabilities = {
      versions: [],
      ciphersuites: [],
      extensions: [],
      proposals: [],
      credentials: [],
    }
    roundtrip(c)
  })

  test("roundtrips nontrivial", () => {
    const c: Capabilities = {
      versions: ["mls10"],
      ciphersuites: ["MLS_256_XWING_AES256GCM_SHA512_Ed25519"],
      extensions: [8, 9],
      proposals: [10, 21],
      credentials: ["basic", "x509"],
    }
    roundtrip(c)
  })
})
