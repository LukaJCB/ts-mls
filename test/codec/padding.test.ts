import { PaddingConfig } from "../../src/paddingConfig.js"
import {
  privateMessageContentDecoder,
  PrivateMessageContent,
  privateMessageContentEncoder,
} from "../../src/privateMessage.js"
import { contentTypes } from "../../src/contentType.js"
import { createRoundtripTest } from "./roundtrip.js"
import { encode } from "../../src/codec/tlsEncoder.js"

describe("PrivateMessageContent roundtrip with padding", () => {
  const roundtrip = (config: PaddingConfig) =>
    createRoundtripTest(privateMessageContentEncoder(config), privateMessageContentDecoder(contentTypes.application))

  const content: PrivateMessageContent = {
    contentType: contentTypes.application,
    applicationData: new Uint8Array(),
    auth: {
      signature: new Uint8Array(),
      contentType: contentTypes.application,
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

    expect(encode(privateMessageContentEncoder(config), content).length).toBe(4000)
  })

  test("fails to decode message with non-zero padding", () => {
    const encoded = encode(privateMessageContentEncoder({ kind: "alwaysPad", paddingLength: 2048 }), content)

    expect(privateMessageContentDecoder(contentTypes.application)(encoded, 0)).toBeDefined()

    encoded[encoded.length - 1024] = 1

    expect(privateMessageContentDecoder(contentTypes.application)(encoded, 0)).toBeUndefined()
  })
})
