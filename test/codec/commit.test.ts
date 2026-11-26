import { commitEncoder, commitDecoder } from "../../src/commit.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { proposalOrRefTypes } from "../../src/proposalOrRefType.js"
import { createRoundtripTest } from "./roundtrip.js"

test.each([
  { description: "missing", bytes: [0] },
  { description: "invalid (2)", bytes: [0, 2] },
  { description: "invalid (255)", bytes: [0, 255] },
])("Commit decoder rejects a $description path-presence byte", ({ bytes }) => {
  expect(commitDecoder(Uint8Array.from(bytes), 0)).toBeUndefined()
})

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
