import { decodePskType, encodePskType, pskTypes } from "../../src/presharedkey.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("PSKTypeValue roundtrip", () => {
  const roundtrip = createRoundtripTest(encodePskType, decodePskType)

  test("roundtrips external", () => {
    roundtrip(pskTypes.external)
  })

  test("roundtrips resumption", () => {
    roundtrip(pskTypes.resumption)
  })
})
