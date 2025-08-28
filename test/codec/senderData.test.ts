import { encodeSenderData, decodeSenderData, ReuseGuard } from "../../src/sender"
import { createRoundtripTest } from "./roundtrip.js"

describe("SenderData roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeSenderData, decodeSenderData)

  test("roundtrips minimal", () => {
    roundtrip({ leafIndex: 0, generation: 0, reuseGuard: new Uint8Array([1, 2, 3, 4]) as ReuseGuard })
  })

  test("roundtrips nonzero", () => {
    roundtrip({ leafIndex: 123, generation: 456, reuseGuard: new Uint8Array([5, 6, 7, 8]) as ReuseGuard })
  })
})
