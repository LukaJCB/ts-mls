import { encodeProposalOrRef, decodeProposalOrRef, proposalOrRefTypes } from "../../src/proposalOrRefType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ProposalOrRef roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeProposalOrRef, decodeProposalOrRef)

  test("roundtrips proposal", () => {
    roundtrip({
      proposalOrRefType: proposalOrRefTypes.proposal,
      proposal: { proposalType: defaultProposalTypes.remove, remove: { removed: 1 } },
    })
  })

  test("roundtrips reference", () => {
    roundtrip({ proposalOrRefType: proposalOrRefTypes.reference, reference: new Uint8Array([1, 2, 3, 4, 5]) })
  })
})
