import { nodeTypeDecoder, nodeTypeEncoder, nodeTypes } from "../../src/nodeType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("NodeTypeValue roundtrip", () => {
  const roundtrip = createRoundtripTest(nodeTypeEncoder, nodeTypeDecoder)

  test("roundtrips leaf", () => {
    roundtrip(nodeTypes.leaf)
  })

  test("roundtrips parent", () => {
    roundtrip(nodeTypes.parent)
  })
})
