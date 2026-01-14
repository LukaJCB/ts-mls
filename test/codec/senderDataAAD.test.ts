import { senderDataAADEncoder, senderDataAADDecoder } from "../../src/sender.js"
import { contentTypes } from "../../src/contentType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("SenderDataAAD roundtrip", () => {
  const roundtrip = createRoundtripTest(senderDataAADEncoder, senderDataAADDecoder)

  test("roundtrips minimal", () => {
    roundtrip({ groupId: new Uint8Array([1]), epoch: 0n, contentType: contentTypes.application })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({ groupId: new Uint8Array([2, 3, 4, 5]), epoch: 123456789n, contentType: contentTypes.commit })
  })
})
