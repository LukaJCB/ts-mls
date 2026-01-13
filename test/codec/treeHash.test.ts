import { encodeTreeHashInput, decodeTreeHashInput } from "../../src/treeHash.js"
import { createRoundtripTest } from "./roundtrip.js"
import { nodeTypes } from "../../src/nodeType.js"

describe("TreeHashInput roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeTreeHashInput, decodeTreeHashInput)

  test("roundtrips leaf", () => {
    roundtrip({ nodeType: nodeTypes.leaf, leafIndex: 0, leafNode: undefined })
  })

  test("roundtrips parent", () => {
    roundtrip({
      nodeType: nodeTypes.parent,
      parentNode: undefined,
      leftHash: new Uint8Array([1, 2]),
      rightHash: new Uint8Array([3, 4]),
    })
  })
})
