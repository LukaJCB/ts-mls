import { Extension, extensionsEqual } from "../src/extension.js"

describe("extensionsEqual", () => {
  test("should return true for identical extensions", () => {
    const ext1: Extension = {
      extensionType: "application_id",
      extensionData: new Uint8Array([1, 2, 3]),
    }
    const ext2: Extension = {
      extensionType: "application_id",
      extensionData: new Uint8Array([1, 2, 3]),
    }

    expect(extensionsEqual([ext1], [ext2])).toBe(true)
  })

  test("should return false for different extension types", () => {
    const ext1: Extension = {
      extensionType: "application_id",
      extensionData: new Uint8Array([1, 2, 3]),
    }
    const ext2: Extension = {
      extensionType: "ratchet_tree",
      extensionData: new Uint8Array([1, 2, 3]),
    }

    expect(extensionsEqual([ext1], [ext2])).toBe(false)
  })

  test("should return false for different extension data", () => {
    const ext1: Extension = {
      extensionType: "application_id",
      extensionData: new Uint8Array([1, 2, 3]),
    }
    const ext2: Extension = {
      extensionType: "application_id",
      extensionData: new Uint8Array([1, 2, 4]),
    }

    expect(extensionsEqual([ext1], [ext2])).toBe(false)
  })

  test("should return false for different array lengths", () => {
    const ext1: Extension = {
      extensionType: "application_id",
      extensionData: new Uint8Array([1, 2, 3]),
    }
    const ext2: Extension = {
      extensionType: "application_id",
      extensionData: new Uint8Array([1, 2, 3]),
    }

    expect(extensionsEqual([ext1], [ext1, ext2])).toBe(false)
  })

  test("should return true for empty arrays", () => {
    expect(extensionsEqual([], [])).toBe(true)
  })
})
