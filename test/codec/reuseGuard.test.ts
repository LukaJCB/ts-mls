import { reuseGuardEncoder, reuseGuardDecoder, ReuseGuard } from "../../src/sender.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ReuseGuard roundtrip", () => {
  const roundtrip = createRoundtripTest(reuseGuardEncoder, reuseGuardDecoder)

  test("roundtrips", () => {
    roundtrip(new Uint8Array([1, 2, 3, 4]) as ReuseGuard)
  })

  test("rejects a buffer shorter than four bytes", () => {
    expect(reuseGuardDecoder(new Uint8Array([1, 2, 3]), 0)).toBeUndefined()
  })

  test("rejects a truncated buffer at a non-zero offset", () => {
    expect(reuseGuardDecoder(new Uint8Array([0, 0, 0, 0, 1, 2]), 4)).toBeUndefined()
  })
})
