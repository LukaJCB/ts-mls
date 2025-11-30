import { encodePskType, decodePskType, PSKTypeName } from "../../src/presharedkey.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("PSKTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodePskType, decodePskType)

  test("roundtrips external", () => {
    roundtrip("external" as PSKTypeName)
  })

  test("roundtrips resumption", () => {
    roundtrip("resumption" as PSKTypeName)
  })
})
