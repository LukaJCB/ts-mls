import {
  LeafNodeExtension,
  GroupContextExtension,
  extensionEncoder,
  leafNodeExtensionDecoder,
  groupContextExtensionDecoder,
} from "../../src/extension.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { createRoundtripTest } from "./roundtrip.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"

describe("Extension roundtrip", () => {
  test("roundtrips minimal", () => {
    const roundtrip = createRoundtripTest(extensionEncoder, leafNodeExtensionDecoder)
    const e: LeafNodeExtension = {
      extensionType: defaultExtensionTypes.application_id,
      extensionData: new Uint8Array([]),
    }
    roundtrip(e)
  })

  test("roundtrips external_senders", () => {
    const roundtrip = createRoundtripTest(extensionEncoder, groupContextExtensionDecoder)
    const e: GroupContextExtension = {
      extensionType: defaultExtensionTypes.external_senders,
      extensionData: {
        signaturePublicKey: new Uint8Array([]),
        credential: {
          credentialType: defaultCredentialTypes.basic,
          identity: new Uint8Array(),
        },
      },
    }
    roundtrip(e)
  })

  test("roundtrips required_capabilities", () => {
    const roundtrip = createRoundtripTest(extensionEncoder, groupContextExtensionDecoder)
    const e: GroupContextExtension = {
      extensionType: defaultExtensionTypes.required_capabilities,
      extensionData: {
        extensionTypes: [6, 7, 8],
        proposalTypes: [9, 10],
        credentialTypes: [defaultCredentialTypes.basic],
      },
    }
    roundtrip(e)
  })
})
