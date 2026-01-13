import {
  decodeProtocolVersion,
  encodeProtocolVersion,
  protocolVersions,
  ProtocolVersionValue,
} from "../../src/protocolVersion.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ProtocolVersionValue roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeProtocolVersion, decodeProtocolVersion)

  test("roundtrips mls10", () => {
    roundtrip(protocolVersions.mls10 as ProtocolVersionValue)
  })
})
