import { senderDataEncoder, senderDataDecoder, ReuseGuard } from "../../src/sender.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("SenderData roundtrip", () => {
  const roundtrip = createRoundtripTest(senderDataEncoder, senderDataDecoder)

  test("roundtrips minimal", () => {
    roundtrip({ leafIndex: 0, generation: 0, reuseGuard: new Uint8Array([1, 2, 3, 4]) as ReuseGuard })
  })

  test("roundtrips nonzero", () => {
    roundtrip({ leafIndex: 123, generation: 456, reuseGuard: new Uint8Array([5, 6, 7, 8]) as ReuseGuard })
  })

  test("rejects a truncated reuse guard", () => {
    const encoded = encode(senderDataEncoder, {
      leafIndex: 1,
      generation: 2,
      reuseGuard: new Uint8Array([9, 10, 11, 12]) as ReuseGuard,
    })

    expect(senderDataDecoder(encoded.subarray(0, encoded.length - 1), 0)).toBeUndefined()
  })
})
