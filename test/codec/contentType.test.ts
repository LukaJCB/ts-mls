import { contentTypeDecoder, contentTypeEncoder, contentTypes, ContentTypeValue } from "../../src/contentType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ContentTypeValue roundtrip", () => {
  const roundtrip = createRoundtripTest(contentTypeEncoder, contentTypeDecoder)

  test("roundtrips minimal", () => {
    roundtrip(contentTypes.application as ContentTypeValue)
  })

  test("roundtrips nontrivial", () => {
    roundtrip(contentTypes.commit as ContentTypeValue)
  })
})
