import { encodeResumptionPSKUsage, decodeResumptionPSKUsage, ResumptionPSKUsageName } from "../../src/presharedkey"
import { createRoundtripTest } from "./roundtrip.js"

describe("ResumptionPSKUsageName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeResumptionPSKUsage, decodeResumptionPSKUsage)

  test("roundtrips application", () => {
    roundtrip("application" as ResumptionPSKUsageName)
  })

  test("roundtrips reinit", () => {
    roundtrip("reinit" as ResumptionPSKUsageName)
  })

  test("roundtrips branch", () => {
    roundtrip("branch" as ResumptionPSKUsageName)
  })
})
