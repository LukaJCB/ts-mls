import { encodePskId, decodePskId } from "../../src/presharedkey"
import { createRoundtripTest } from "./roundtrip.js"

describe("PreSharedKeyID roundtrip", () => {
  const roundtrip = createRoundtripTest(encodePskId, decodePskId)

  test("roundtrips external", () => {
    roundtrip({ psktype: "external", pskId: new Uint8Array([1, 2, 3]), pskNonce: new Uint8Array([4, 5, 6, 7]) })
  })

  test("roundtrips resumption", () => {
    roundtrip({
      psktype: "resumption",
      usage: "application",
      pskGroupId: new Uint8Array([8, 9, 10]),
      pskEpoch: 123n,
      pskNonce: new Uint8Array([11, 12, 13, 14]),
    })
  })
})
