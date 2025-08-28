import { encodePskInfo, decodePskInfo } from "../../src/presharedkey"
import { createRoundtripTest } from "./roundtrip.js"

describe("PSKInfo roundtrip", () => {
  const roundtrip = createRoundtripTest(encodePskInfo, decodePskInfo)

  test("roundtrips external", () => {
    roundtrip({ psktype: "external", pskId: new Uint8Array([1, 2, 3]) })
  })

  test("roundtrips resumption", () => {
    roundtrip({ psktype: "resumption", usage: "application", pskGroupId: new Uint8Array([4, 5, 6]), pskEpoch: 123n })
  })
})
