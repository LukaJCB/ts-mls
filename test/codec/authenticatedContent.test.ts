import { authenticatedContentEncoder, decodeAuthenticatedContent } from "../../src/authenticatedContent.js"
import { contentTypes } from "../../src/contentType.js"
import { createRoundtripTest } from "./roundtrip.js"
import { senderTypes } from "../../src/sender.js"
import { wireformats } from "../../src/wireformat.js"

describe("AuthenticatedContent roundtrip", () => {
  const roundtrip = createRoundtripTest(authenticatedContentEncoder, decodeAuthenticatedContent)

  test("roundtrips minimal", () => {
    roundtrip({
      wireformat: wireformats.mls_public_message,
      content: {
        contentType: contentTypes.application,
        groupId: new Uint8Array([1]),
        epoch: 0n,
        sender: { senderType: senderTypes.member, leafIndex: 0 },
        authenticatedData: new Uint8Array([2]),
        applicationData: new Uint8Array([3]),
      },
      auth: { contentType: contentTypes.application, signature: new Uint8Array([4, 5, 6]) },
    })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({
      wireformat: wireformats.mls_private_message,
      content: {
        contentType: contentTypes.commit,
        groupId: new Uint8Array([7, 8, 9]),
        epoch: 123n,
        sender: { senderType: senderTypes.external, senderIndex: 1 },
        authenticatedData: new Uint8Array([10, 11, 12]),
        commit: { proposals: [], path: undefined },
      },
      auth: {
        contentType: contentTypes.commit,
        signature: new Uint8Array([13, 14, 15, 16]),
        confirmationTag: new Uint8Array([17, 18, 19]),
      },
    })
  })
})
