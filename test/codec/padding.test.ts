import { PaddingConfig } from "../../src/paddingConfig"
import {
  encodePrivateMessageContent,
  decodePrivateMessageContent,
  PrivateMessageContent,
} from "../../src/privateMessage"
import { createRoundtripTest } from "./roundtrip.js"

describe("PrivateMessageContent roundtrip with padding", () => {
  const roundtrip = (config: PaddingConfig) =>
    createRoundtripTest(encodePrivateMessageContent(config), decodePrivateMessageContent("application"))

  const content: PrivateMessageContent = {
    contentType: "application",
    applicationData: new Uint8Array(),
    auth: {
      signature: new Uint8Array(),
      contentType: "application",
    },
  }

  test("roundtrips application with no padding", () => {
    roundtrip({ kind: "alwaysPad", paddingLength: 0 })(content)
  })

  test("roundtrips application with 64 bytes of padding", () => {
    roundtrip({ kind: "alwaysPad", paddingLength: 64 })(content)
  })

  test("roundtrips application with 256 bytes of padding", () => {
    roundtrip({ kind: "alwaysPad", paddingLength: 256 })(content)
  })

  test("roundtrips application with 5000 bytes of padding", () => {
    roundtrip({ kind: "alwaysPad", paddingLength: 5000 })(content)
  })

  test("roundtrips application with 80000 bytes of padding", () => {
    roundtrip({ kind: "alwaysPad", paddingLength: 80000 })(content)
  })

  test("roundtrips application with padding until 4000 bytes", () => {
    const config: PaddingConfig = { kind: "padUntilLength", padUntilLength: 4000 }
    roundtrip(config)(content)

    expect(encodePrivateMessageContent(config)(content).length).toBe(4000)
  })

  test("fails to decode message with non-zero padding", () => {
    const encoded = encodePrivateMessageContent({ kind: "alwaysPad", paddingLength: 2048 })(content)

    expect(decodePrivateMessageContent("application")(encoded, 0)).toBeDefined()

    encoded[encoded.length - 1024] = 1

    expect(decodePrivateMessageContent("application")(encoded, 0)).toBeUndefined()
  })
})
