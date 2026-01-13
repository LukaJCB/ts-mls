import { decodeResumptionPSKUsage, encodeResumptionPSKUsage, resumptionPSKUsages } from "../../src/presharedkey.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ResumptionPSKUsageValue roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeResumptionPSKUsage, decodeResumptionPSKUsage)

  test("roundtrips application", () => {
    roundtrip(resumptionPSKUsages.application)
  })

  test("roundtrips reinit", () => {
    roundtrip(resumptionPSKUsages.reinit)
  })

  test("roundtrips branch", () => {
    roundtrip(resumptionPSKUsages.branch)
  })
})
