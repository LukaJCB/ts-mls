import { encodeParentNode, decodeParentNode, ParentNode } from "../../src/parentNode.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ParentNode roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeParentNode, decodeParentNode)

  test("roundtrips minimal", () => {
    const node: ParentNode = {
      hpkePublicKey: new Uint8Array([]),
      parentHash: new Uint8Array([]),
      unmergedLeaves: [],
    }
    roundtrip(node)
  })

  test("roundtrips nontrivial", () => {
    const node: ParentNode = {
      hpkePublicKey: new Uint8Array([1, 2, 3]),
      parentHash: new Uint8Array([4, 5, 6]),
      unmergedLeaves: [7, 8, 9],
    }
    roundtrip(node)
  })
})
