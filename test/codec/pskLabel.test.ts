import { encodePskLabel, decodePskLabel } from "../../src/presharedkey"
import { createRoundtripTest } from "./roundtrip.js"

describe("PSKLabel roundtrip", () => {
  const roundtrip = createRoundtripTest(encodePskLabel, decodePskLabel)

  test("roundtrips minimal", () => {
    roundtrip({
      id: { psktype: "external", pskId: new Uint8Array([1]), pskNonce: new Uint8Array([2, 3, 4, 5]) },
      index: 0,
      count: 1,
    })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({
      id: {
        psktype: "resumption",
        usage: "application",
        pskGroupId: new Uint8Array([6, 7, 8]),
        pskEpoch: 123n,
        pskNonce: new Uint8Array([9, 10, 11, 12]),
      },
      index: 5,
      count: 10,
    })
  })
})
