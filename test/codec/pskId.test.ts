import { decodePskId, pskIdEncoder, pskTypes, resumptionPSKUsages } from "../../src/presharedkey.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("PreSharedKeyID roundtrip", () => {
  const roundtrip = createRoundtripTest(pskIdEncoder, decodePskId)

  test("roundtrips external", () => {
    roundtrip({ psktype: pskTypes.external, pskId: new Uint8Array([1, 2, 3]), pskNonce: new Uint8Array([4, 5, 6, 7]) })
  })

  test("roundtrips resumption", () => {
    roundtrip({
      psktype: pskTypes.resumption,
      usage: resumptionPSKUsages.application,
      pskGroupId: new Uint8Array([8, 9, 10]),
      pskEpoch: 123n,
      pskNonce: new Uint8Array([11, 12, 13, 14]),
    })
  })
})
