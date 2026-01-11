import { encodeProposalOrRefType, decodeProposalOrRefType, proposalOrRefTypes } from "../../src/proposalOrRefType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ProposalOrRefTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeProposalOrRefType, decodeProposalOrRefType)

  test("roundtrips proposal", () => {
    roundtrip(proposalOrRefTypes.proposal)
  })

  test("roundtrips reference", () => {
    roundtrip(proposalOrRefTypes.reference)
  })
})
