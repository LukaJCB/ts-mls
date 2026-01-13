import { proposalOrRefTypeEncoder, decodeProposalOrRefType, proposalOrRefTypes } from "../../src/proposalOrRefType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ProposalOrRefTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(proposalOrRefTypeEncoder, decodeProposalOrRefType)

  test("roundtrips proposal", () => {
    roundtrip(proposalOrRefTypes.proposal)
  })

  test("roundtrips reference", () => {
    roundtrip(proposalOrRefTypes.reference)
  })
})
