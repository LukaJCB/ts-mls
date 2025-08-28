import { encodeParentHashInput, decodeParentHashInput } from "../../src/parentHash"
import { createRoundtripTest } from "./roundtrip.js"

describe("ParentHashInput roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeParentHashInput, decodeParentHashInput)

  test("roundtrips", () => {
    roundtrip({
      encryptionKey: new Uint8Array([1]),
      parentHash: new Uint8Array([2]),
      originalSiblingTreeHash: new Uint8Array([3]),
    })
  })
})
