import { privateContentAADEncoder, privateContentAADDecoder } from "../../src/privateMessage.js"
import { contentTypes } from "../../src/contentType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("PrivateContentAAD roundtrip", () => {
  const roundtrip = createRoundtripTest(privateContentAADEncoder, privateContentAADDecoder)

  test("roundtrips application", () => {
    roundtrip({
      groupId: new Uint8Array([1]),
      epoch: 0n,
      contentType: contentTypes.application,
      authenticatedData: new Uint8Array([2]),
    })
  })

  test("roundtrips commit", () => {
    roundtrip({
      groupId: new Uint8Array([3, 4, 5]),
      epoch: 123n,
      contentType: contentTypes.commit,
      authenticatedData: new Uint8Array([6, 7, 8]),
    })
  })

  test("roundtrips proposal", () => {
    roundtrip({
      groupId: new Uint8Array([3, 4, 5]),
      epoch: 123n,
      contentType: contentTypes.proposal,
      authenticatedData: new Uint8Array([6, 7, 8]),
    })
  })
})
