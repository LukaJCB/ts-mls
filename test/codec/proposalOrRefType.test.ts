import { proposalOrRefTypeEncoder, proposalOrRefTypeDecoder, proposalOrRefTypes } from "../../src/proposalOrRefType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ProposalOrRefTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(proposalOrRefTypeEncoder, proposalOrRefTypeDecoder)

  test("roundtrips proposal", () => {
    roundtrip(proposalOrRefTypes.proposal)
  })

  test("roundtrips reference", () => {
    roundtrip(proposalOrRefTypes.reference)
  })
})
