import { leafNodeSourceValueEncoder, decodeLeafNodeSourceValue, leafNodeSources } from "../../src/leafNodeSource.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("LeafNodeSourceValue roundtrip", () => {
  const roundtrip = createRoundtripTest(leafNodeSourceValueEncoder, decodeLeafNodeSourceValue)

  test("roundtrips key_package", () => {
    roundtrip(leafNodeSources.key_package)
  })

  test("roundtrips commit", () => {
    roundtrip(leafNodeSources.commit)
  })

  test("roundtrips update", () => {
    roundtrip(leafNodeSources.update)
  })
})
