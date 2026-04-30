import { contentTypeDecoder, contentTypeEncoder, contentTypes } from "../../src/contentType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ContentTypeValue roundtrip", () => {
  const roundtrip = createRoundtripTest(contentTypeEncoder, contentTypeDecoder)

  test("roundtrips minimal", () => {
    roundtrip(contentTypes.application)
  })

  test("roundtrips nontrivial", () => {
    roundtrip(contentTypes.commit)
  })
})
