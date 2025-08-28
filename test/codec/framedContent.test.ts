import { encodeFramedContent, decodeFramedContent } from "../../src/framedContent"
import { createRoundtripTest } from "./roundtrip.js"

describe("FramedContent roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeFramedContent, decodeFramedContent)

  test("roundtrips application", () => {
    roundtrip({
      contentType: "application",
      groupId: new Uint8Array([1]),
      epoch: 0n,
      sender: { senderType: "member", leafIndex: 0 },
      authenticatedData: new Uint8Array([2]),
      applicationData: new Uint8Array([3]),
    })
  })

  test("roundtrips commit", () => {
    roundtrip({
      contentType: "commit",
      groupId: new Uint8Array([4, 5]),
      epoch: 1n,
      sender: { senderType: "external", senderIndex: 1 },
      authenticatedData: new Uint8Array([6, 7]),
      commit: { proposals: [], path: undefined },
    })
  })
})
