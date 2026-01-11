import { decodeSenderType, encodeSenderType, senderTypes, SenderTypeValue } from "../../src/sender.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("SenderTypeValue roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeSenderType, decodeSenderType)

  test("roundtrips member", () => {
    roundtrip(senderTypes.member as SenderTypeValue)
  })

  test("roundtrips external", () => {
    roundtrip(senderTypes.external as SenderTypeValue)
  })

  test("roundtrips new_member_proposal", () => {
    roundtrip(senderTypes.new_member_proposal as SenderTypeValue)
  })

  test("roundtrips new_member_commit", () => {
    roundtrip(senderTypes.new_member_commit as SenderTypeValue)
  })
})
