import { wireformatEncoder, wireformatDecoder, wireformats } from "../../src/wireformat.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("WireformatName roundtrip", () => {
  const roundtrip = createRoundtripTest(wireformatEncoder, wireformatDecoder)

  test("roundtrips mls_public_message", () => {
    roundtrip(wireformats.mls_public_message)
  })

  test("roundtrips mls_private_message", () => {
    roundtrip(wireformats.mls_private_message)
  })

  test("roundtrips mls_welcome", () => {
    roundtrip(wireformats.mls_welcome)
  })

  test("roundtrips group_info", () => {
    roundtrip(wireformats.mls_group_info)
  })

  test("roundtrips mls_key_package", () => {
    roundtrip(wireformats.mls_key_package)
  })
})
