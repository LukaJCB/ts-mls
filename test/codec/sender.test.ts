import { encodeSender, decodeSender } from "../../src/sender"
import { createRoundtripTest } from "./roundtrip.js"

describe("Sender roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeSender, decodeSender)

  test("roundtrips member", () => {
    roundtrip({ senderType: "member", leafIndex: 0 })
  })

  test("roundtrips external", () => {
    roundtrip({ senderType: "external", senderIndex: 1 })
  })

  test("roundtrips new_member_proposal", () => {
    roundtrip({ senderType: "new_member_proposal" })
  })

  test("roundtrips new_member_commit", () => {
    roundtrip({ senderType: "new_member_commit" })
  })
})
