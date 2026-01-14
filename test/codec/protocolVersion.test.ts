import {
  protocolVersionDecoder,
  protocolVersionEncoder,
  protocolVersions,
  ProtocolVersionValue,
} from "../../src/protocolVersion.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ProtocolVersionValue roundtrip", () => {
  const roundtrip = createRoundtripTest(protocolVersionEncoder, protocolVersionDecoder)

  test("roundtrips mls10", () => {
    roundtrip(protocolVersions.mls10 as ProtocolVersionValue)
  })
})
