import { senderEncoder, decodeSender, senderTypes } from "../../src/sender.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("Sender roundtrip", () => {
  const roundtrip = createRoundtripTest(senderEncoder, decodeSender)

  test("roundtrips member", () => {
    roundtrip({ senderType: senderTypes.member, leafIndex: 0 })
  })

  test("roundtrips external", () => {
    roundtrip({ senderType: senderTypes.external, senderIndex: 1 })
  })

  test("roundtrips new_member_proposal", () => {
    roundtrip({ senderType: senderTypes.new_member_proposal })
  })

  test("roundtrips new_member_commit", () => {
    roundtrip({ senderType: senderTypes.new_member_commit })
  })
})
