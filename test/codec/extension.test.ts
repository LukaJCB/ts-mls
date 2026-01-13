import { encodeExtension, decodeExtension, Extension } from "../../src/extension.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("Extension roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeExtension, decodeExtension)

  test("roundtrips minimal", () => {
    const e: Extension = {
      extensionType: defaultExtensionTypes.application_id,
      extensionData: new Uint8Array([]),
    }
    roundtrip(e)
  })

  test("roundtrips nontrivial", () => {
    const e: Extension = {
      extensionType: defaultExtensionTypes.ratchet_tree,
      extensionData: new Uint8Array([1, 2, 3, 4]),
    }
    roundtrip(e)
  })
})
