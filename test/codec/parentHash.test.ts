import { parentHashInputEncoder, decodeParentHashInput } from "../../src/parentHash.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ParentHashInput roundtrip", () => {
  const roundtrip = createRoundtripTest(parentHashInputEncoder, decodeParentHashInput)

  test("roundtrips", () => {
    roundtrip({
      encryptionKey: new Uint8Array([1]),
      parentHash: new Uint8Array([2]),
      originalSiblingTreeHash: new Uint8Array([3]),
    })
  })
})
