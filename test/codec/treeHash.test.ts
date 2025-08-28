import { encodeTreeHashInput, decodeTreeHashInput } from "../../src/treeHash"
import { createRoundtripTest } from "./roundtrip.js"

describe("TreeHashInput roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeTreeHashInput, decodeTreeHashInput)

  test("roundtrips leaf", () => {
    roundtrip({ nodeType: "leaf", leafIndex: 0, leafNode: undefined })
  })

  test("roundtrips parent", () => {
    roundtrip({
      nodeType: "parent",
      parentNode: undefined,
      leftHash: new Uint8Array([1, 2]),
      rightHash: new Uint8Array([3, 4]),
    })
  })
})
