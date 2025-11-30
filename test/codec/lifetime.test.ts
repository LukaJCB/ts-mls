import { encodeLifetime, decodeLifetime } from "../../src/lifetime.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("Lifetime roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeLifetime, decodeLifetime)

  test("roundtrips minimal", () => {
    roundtrip({ notBefore: 0n, notAfter: 0n })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({ notBefore: 123456789n, notAfter: 987654321n })
  })
})
