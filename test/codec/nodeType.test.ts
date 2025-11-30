import { encodeNodeType, decodeNodeType, NodeTypeName } from "../../src/nodeType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("NodeTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeNodeType, decodeNodeType)

  test("roundtrips leaf", () => {
    roundtrip("leaf" as NodeTypeName)
  })

  test("roundtrips parent", () => {
    roundtrip("parent" as NodeTypeName)
  })
})
