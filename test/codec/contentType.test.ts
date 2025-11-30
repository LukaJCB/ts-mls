import { encodeContentType, decodeContentType, ContentTypeName } from "../../src/contentType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ContentTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeContentType, decodeContentType)

  test("roundtrips minimal", () => {
    roundtrip("application" as ContentTypeName)
  })

  test("roundtrips nontrivial", () => {
    roundtrip("commit" as ContentTypeName)
  })
})
