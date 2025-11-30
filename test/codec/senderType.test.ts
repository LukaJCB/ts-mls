import { encodeSenderType, decodeSenderType, SenderTypeName } from "../../src/sender.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("SenderTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeSenderType, decodeSenderType)

  test("roundtrips member", () => {
    roundtrip("member" as SenderTypeName)
  })

  test("roundtrips external", () => {
    roundtrip("external" as SenderTypeName)
  })

  test("roundtrips new_member_proposal", () => {
    roundtrip("new_member_proposal" as SenderTypeName)
  })

  test("roundtrips new_member_commit", () => {
    roundtrip("new_member_commit" as SenderTypeName)
  })
})
