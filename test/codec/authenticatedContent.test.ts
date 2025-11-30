import { encodeAuthenticatedContent, decodeAuthenticatedContent } from "../../src/authenticatedContent.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("AuthenticatedContent roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeAuthenticatedContent, decodeAuthenticatedContent)

  test("roundtrips minimal", () => {
    roundtrip({
      wireformat: "mls_public_message",
      content: {
        contentType: "application",
        groupId: new Uint8Array([1]),
        epoch: 0n,
        sender: { senderType: "member", leafIndex: 0 },
        authenticatedData: new Uint8Array([2]),
        applicationData: new Uint8Array([3]),
      },
      auth: { contentType: "application", signature: new Uint8Array([4, 5, 6]) },
    })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({
      wireformat: "mls_private_message",
      content: {
        contentType: "commit",
        groupId: new Uint8Array([7, 8, 9]),
        epoch: 123n,
        sender: { senderType: "external", senderIndex: 1 },
        authenticatedData: new Uint8Array([10, 11, 12]),
        commit: { proposals: [], path: undefined },
      },
      auth: {
        contentType: "commit",
        signature: new Uint8Array([13, 14, 15, 16]),
        confirmationTag: new Uint8Array([17, 18, 19]),
      },
    })
  })
})
