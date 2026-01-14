import { decodePskInfo, pskInfoEncoder, pskTypes, resumptionPSKUsages } from "../../src/presharedkey.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("PSKInfo roundtrip", () => {
  const roundtrip = createRoundtripTest(pskInfoEncoder, decodePskInfo)

  test("roundtrips external", () => {
    roundtrip({ psktype: pskTypes.external, pskId: new Uint8Array([1, 2, 3]) })
  })

  test("roundtrips resumption", () => {
    roundtrip({
      psktype: pskTypes.resumption,
      usage: resumptionPSKUsages.application,
      pskGroupId: new Uint8Array([4, 5, 6]),
      pskEpoch: 123n,
    })
  })
})
