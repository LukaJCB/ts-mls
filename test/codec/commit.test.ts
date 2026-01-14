import { commitEncoder, commitDecoder } from "../../src/commit.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { proposalOrRefTypes } from "../../src/proposalOrRefType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("Commit roundtrip", () => {
  const roundtrip = createRoundtripTest(commitEncoder, commitDecoder)

  test("roundtrips minimal", () => {
    roundtrip({ proposals: [], path: undefined })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({
      proposals: [
        {
          proposalOrRefType: proposalOrRefTypes.proposal,
          proposal: { proposalType: defaultProposalTypes.remove, remove: { removed: 1 } },
        },
      ],
      path: undefined,
    })
  })
})
