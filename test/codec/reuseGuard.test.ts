import { reuseGuardEncoder, decodeReuseGuard, ReuseGuard } from "../../src/sender.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ReuseGuard roundtrip", () => {
  const roundtrip = createRoundtripTest(reuseGuardEncoder, decodeReuseGuard)

  test("roundtrips", () => {
    roundtrip(new Uint8Array([1, 2, 3, 4]) as ReuseGuard)
  })
})
