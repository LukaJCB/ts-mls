import { decodeNodeType, encodeNodeType, nodeTypes, NodeTypeValue } from "../../src/nodeType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("NodeTypeValue roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeNodeType, decodeNodeType)

  test("roundtrips leaf", () => {
    roundtrip(nodeTypes.leaf as NodeTypeValue)
  })

  test("roundtrips parent", () => {
    roundtrip(nodeTypes.parent as NodeTypeValue)
  })
})
