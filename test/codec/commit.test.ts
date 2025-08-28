import { encodeCommit, decodeCommit } from "../../src/commit"
import { createRoundtripTest } from "./roundtrip.js"

describe("Commit roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeCommit, decodeCommit)

  test("roundtrips minimal", () => {
    roundtrip({ proposals: [], path: undefined })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({
      proposals: [{ proposalOrRefType: "proposal", proposal: { proposalType: "remove", remove: { removed: 1 } } }],
      path: undefined,
    })
  })
})
