import { encodePublicMessage, decodePublicMessage } from "../../src/publicMessage.js"
import { createRoundtripTest } from "./roundtrip.js"
import { contentTypes } from "../../src/contentType.js"
import { senderTypes } from "../../src/sender.js"

describe("PublicMessage roundtrip", () => {
  const roundtrip = createRoundtripTest(encodePublicMessage, decodePublicMessage)

  test("roundtrips member", () => {
    roundtrip({
      content: {
        contentType: contentTypes.application,
        groupId: new Uint8Array([1]),
        epoch: 0n,
        sender: { senderType: senderTypes.member, leafIndex: 0 },
        authenticatedData: new Uint8Array([2]),
        applicationData: new Uint8Array([3]),
      },
      auth: { contentType: contentTypes.application, signature: new Uint8Array([4, 5, 6]) },
      senderType: senderTypes.member,
      membershipTag: new Uint8Array([7, 8, 9]),
    })
  })

  test("roundtrips external", () => {
    roundtrip({
      content: {
        contentType: contentTypes.commit,
        groupId: new Uint8Array([10, 11]),
        epoch: 1n,
        sender: { senderType: senderTypes.external, senderIndex: 1 },
        authenticatedData: new Uint8Array([12, 13]),
        commit: { proposals: [], path: undefined },
      },
      auth: {
        contentType: contentTypes.commit,
        signature: new Uint8Array([14, 15, 16]),
        confirmationTag: new Uint8Array([17, 18, 19]),
      },
      senderType: senderTypes.external,
    })
  })
})
