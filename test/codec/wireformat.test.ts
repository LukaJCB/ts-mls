import { encodeWireformat, decodeWireformat, WireformatName } from "../../src/wireformat.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("WireformatName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeWireformat, decodeWireformat)

  test("roundtrips mls_public_message", () => {
    roundtrip("mls_public_message" as WireformatName)
  })

  test("roundtrips mls_private_message", () => {
    roundtrip("mls_private_message" as WireformatName)
  })

  test("roundtrips mls_welcome", () => {
    roundtrip("mls_welcome" as WireformatName)
  })

  test("roundtrips group_info", () => {
    roundtrip("mls_group_info" as WireformatName)
  })

  test("roundtrips mls_key_package", () => {
    roundtrip("mls_key_package" as WireformatName)
  })
})
