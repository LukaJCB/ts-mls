import { senderTypeDecoder, senderTypeEncoder, senderTypes } from "../../src/sender.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("SenderTypeValue roundtrip", () => {
  const roundtrip = createRoundtripTest(senderTypeEncoder, senderTypeDecoder)

  test("roundtrips member", () => {
    roundtrip(senderTypes.member)
  })

  test("roundtrips external", () => {
    roundtrip(senderTypes.external)
  })

  test("roundtrips new_member_proposal", () => {
    roundtrip(senderTypes.new_member_proposal)
  })

  test("roundtrips new_member_commit", () => {
    roundtrip(senderTypes.new_member_commit)
  })
})
