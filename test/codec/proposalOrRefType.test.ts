import { encodeProposalOrRefType, decodeProposalOrRefType, ProposalOrRefTypeName } from "../../src/proposalOrRefType"
import { createRoundtripTest } from "./roundtrip.js"

describe("ProposalOrRefTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeProposalOrRefType, decodeProposalOrRefType)

  test("roundtrips proposal", () => {
    roundtrip("proposal" as ProposalOrRefTypeName)
  })

  test("roundtrips reference", () => {
    roundtrip("reference" as ProposalOrRefTypeName)
  })
})
