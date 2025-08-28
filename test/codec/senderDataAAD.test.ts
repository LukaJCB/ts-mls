import { encodeSenderDataAAD, decodeSenderDataAAD } from "../../src/sender"
import { createRoundtripTest } from "./roundtrip.js"

describe("SenderDataAAD roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeSenderDataAAD, decodeSenderDataAAD)

  test("roundtrips minimal", () => {
    roundtrip({ groupId: new Uint8Array([1]), epoch: 0n, contentType: "application" })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({ groupId: new Uint8Array([2, 3, 4, 5]), epoch: 123456789n, contentType: "commit" })
  })
})
