import { decodePskType, pskTypeEncoder, pskTypes } from "../../src/presharedkey.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("PSKTypeValue roundtrip", () => {
  const roundtrip = createRoundtripTest(pskTypeEncoder, decodePskType)

  test("roundtrips external", () => {
    roundtrip(pskTypes.external)
  })

  test("roundtrips resumption", () => {
    roundtrip(pskTypes.resumption)
  })
})
