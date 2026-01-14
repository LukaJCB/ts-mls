import { nodeTypeDecoder, nodeTypeEncoder, nodeTypes, NodeTypeValue } from "../../src/nodeType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("NodeTypeValue roundtrip", () => {
  const roundtrip = createRoundtripTest(nodeTypeEncoder, nodeTypeDecoder)

  test("roundtrips leaf", () => {
    roundtrip(nodeTypes.leaf as NodeTypeValue)
  })

  test("roundtrips parent", () => {
    roundtrip(nodeTypes.parent as NodeTypeValue)
  })
})
