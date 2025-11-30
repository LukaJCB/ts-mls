import { encodeProposalOrRef, decodeProposalOrRef } from "../../src/proposalOrRefType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ProposalOrRef roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeProposalOrRef, decodeProposalOrRef)

  test("roundtrips proposal", () => {
    roundtrip({ proposalOrRefType: "proposal", proposal: { proposalType: "remove", remove: { removed: 1 } } })
  })

  test("roundtrips reference", () => {
    roundtrip({ proposalOrRefType: "reference", reference: new Uint8Array([1, 2, 3, 4, 5]) })
  })
})
