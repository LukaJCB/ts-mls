import {
  encodeDefaultExtensionType,
  decodeDefaultExtensionType,
  DefaultExtensionTypeName,
} from "../../src/defaultExtensionType"
import { createRoundtripTest } from "./roundtrip.js"

describe("DefaultExtensionTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeDefaultExtensionType, decodeDefaultExtensionType)

  test("roundtrips application_id", () => {
    roundtrip("application_id" as DefaultExtensionTypeName)
  })

  test("roundtrips external_senders", () => {
    roundtrip("external_senders" as DefaultExtensionTypeName)
  })
})
