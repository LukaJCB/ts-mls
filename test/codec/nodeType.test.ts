import { encodeNodeType, decodeNodeType, NodeTypeName } from "../../src/nodeType"
import { createRoundtripTest } from "./roundtrip"

describe("NodeTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeNodeType, decodeNodeType)

  test("roundtrips leaf", () => {
    roundtrip("leaf" as NodeTypeName)
  })

  test("roundtrips parent", () => {
    roundtrip("parent" as NodeTypeName)
  })
})
