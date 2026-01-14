import { decodeExtension, LeafNodeExtension, GroupContextExtension, extensionEncoder } from "../../src/extension.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { createRoundtripTest } from "./roundtrip.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { externalSenderEncoder } from "../../src/externalSender.js"
import { requiredCapabilitiesEncoder } from "../../src/requiredCapabilities.js"

describe("Extension roundtrip", () => {
  const roundtrip = createRoundtripTest(extensionEncoder, decodeExtension)

  test("roundtrips minimal", () => {
    const e: LeafNodeExtension = {
      extensionType: defaultExtensionTypes.application_id,
      extensionData: new Uint8Array([]),
    }
    roundtrip(e)
  })

  test("roundtrips external_senders", () => {
    const e: GroupContextExtension = {
      extensionType: defaultExtensionTypes.external_senders,
      extensionData: encode(externalSenderEncoder, {
        signaturePublicKey: new Uint8Array([]),
        credential: {
          credentialType: defaultCredentialTypes.basic,
          identity: new Uint8Array(),
        },
      }),
    }
    roundtrip(e)
  })

  test("roundtrips required_capabilities", () => {
    const e: GroupContextExtension = {
      extensionType: defaultExtensionTypes.required_capabilities,
      extensionData: encode(requiredCapabilitiesEncoder, {
        extensionTypes: [6, 7, 8],
        proposalTypes: [9, 10],
        credentialTypes: [defaultCredentialTypes.basic],
      }),
    }
    roundtrip(e)
  })
})
