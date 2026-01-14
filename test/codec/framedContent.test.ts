import { framedContentEncoder, framedContentDecoder } from "../../src/framedContent.js"
import { contentTypes } from "../../src/contentType.js"
import { createRoundtripTest } from "./roundtrip.js"
import { senderTypes } from "../../src/sender.js"

describe("FramedContent roundtrip", () => {
  const roundtrip = createRoundtripTest(framedContentEncoder, framedContentDecoder)

  test("roundtrips application", () => {
    roundtrip({
      contentType: contentTypes.application,
      groupId: new Uint8Array([1]),
      epoch: 0n,
      sender: { senderType: senderTypes.member, leafIndex: 0 },
      authenticatedData: new Uint8Array([2]),
      applicationData: new Uint8Array([3]),
    })
  })

  test("roundtrips commit", () => {
    roundtrip({
      contentType: contentTypes.commit,
      groupId: new Uint8Array([4, 5]),
      epoch: 1n,
      sender: { senderType: senderTypes.external, senderIndex: 1 },
      authenticatedData: new Uint8Array([6, 7]),
      commit: { proposals: [], path: undefined },
    })
  })
})
