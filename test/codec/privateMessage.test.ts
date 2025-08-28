import { encodePrivateMessage, decodePrivateMessage } from "../../src/privateMessage"
import { createRoundtripTest } from "./roundtrip.js"

describe("PrivateMessage roundtrip", () => {
  const roundtrip = createRoundtripTest(encodePrivateMessage, decodePrivateMessage)

  test("roundtrips application", () => {
    roundtrip({
      groupId: new Uint8Array([1]),
      epoch: 0n,
      contentType: "application",
      authenticatedData: new Uint8Array([2]),
      encryptedSenderData: new Uint8Array([3]),
      ciphertext: new Uint8Array([4]),
    })
  })

  test("roundtrips commit", () => {
    roundtrip({
      groupId: new Uint8Array([5, 6]),
      epoch: 123n,
      contentType: "commit",
      authenticatedData: new Uint8Array([7, 8]),
      encryptedSenderData: new Uint8Array([9, 10]),
      ciphertext: new Uint8Array([11, 12, 13]),
    })
  })

  test("roundtrips proposal", () => {
    roundtrip({
      groupId: new Uint8Array([5, 6]),
      epoch: 123n,
      contentType: "proposal",
      authenticatedData: new Uint8Array([7, 8]),
      encryptedSenderData: new Uint8Array([9, 10]),
      ciphertext: new Uint8Array([11, 12, 13]),
    })
  })
})
