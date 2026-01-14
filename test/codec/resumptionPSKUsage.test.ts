import { resumptionPSKUsageDecoder, resumptionPSKUsageEncoder, resumptionPSKUsages } from "../../src/presharedkey.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ResumptionPSKUsageValue roundtrip", () => {
  const roundtrip = createRoundtripTest(resumptionPSKUsageEncoder, resumptionPSKUsageDecoder)

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
