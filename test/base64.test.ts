import { bytesToBase64, base64ToBytes } from "../src/util/byteArray.js"

describe("base64", () => {
  describe("bytesToBase64", () => {
    test("should convert empty array to empty string", () => {
      const result = bytesToBase64(new Uint8Array())
      expect(result).toBe("")
    })

    test("should convert simple bytes to base64", () => {
      const bytes = new Uint8Array([1, 2, 3, 4])
      const result = bytesToBase64(bytes)
      expect(result).toBe("AQIDBA==")
    })

    test("should convert bytes with all zeros", () => {
      const bytes = new Uint8Array([0, 0, 0, 0])
      const result = bytesToBase64(bytes)
      expect(result).toBe("AAAAAA==")
    })

    test("should convert bytes with high values", () => {
      const bytes = new Uint8Array([255, 255, 255, 255])
      const result = bytesToBase64(bytes)
      expect(result).toBe("/////w==")
    })

    test("should handle single byte", () => {
      const bytes = new Uint8Array([65]) // ASCII 'A'
      const result = bytesToBase64(bytes)
      expect(result).toBe("QQ==")
    })

    test("should handle two bytes", () => {
      const bytes = new Uint8Array([65, 66]) // ASCII 'AB'
      const result = bytesToBase64(bytes)
      expect(result).toBe("QUI=")
    })
  })

  describe("base64ToBytes", () => {
    test("should convert empty string to empty array", () => {
      const result = base64ToBytes("")
      expect(result).toEqual(new Uint8Array())
    })

    test("should convert base64 to bytes", () => {
      const result = base64ToBytes("AQIDBA==")
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4]))
    })

    test("should convert base64 with all zeros", () => {
      const result = base64ToBytes("AAAAAA==")
      expect(result).toEqual(new Uint8Array([0, 0, 0, 0]))
    })

    test("should convert base64 with high values", () => {
      const result = base64ToBytes("/////w==")
      expect(result).toEqual(new Uint8Array([255, 255, 255, 255]))
    })

    test("should handle single character", () => {
      const result = base64ToBytes("QQ==")
      expect(result).toEqual(new Uint8Array([65]))
    })

    test("should handle two characters", () => {
      const result = base64ToBytes("QUI=")
      expect(result).toEqual(new Uint8Array([65, 66]))
    })

    test("should roundtrip correctly", () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
      const base64 = bytesToBase64(original)
      const converted = base64ToBytes(base64)
      expect(converted).toEqual(original)
    })
  })

  describe("base64ToBytes (Browser atob path)", () => {
    const originalBuffer = globalThis.Buffer
    const originalAtob = globalThis.atob

    beforeAll(() => {
      // Simulate browser: remove Buffer and add atob
      // @ts-expect-error
      delete globalThis.Buffer
      globalThis.atob = (str: string) => originalBuffer.from(str, "base64").toString("binary")
    })

    afterAll(() => {
      globalThis.Buffer = originalBuffer
      globalThis.atob = originalAtob
    })

    test("decodes using browser atob when Buffer is not defined", () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
      const base64 = bytesToBase64(original)
      const converted = base64ToBytes(base64)
      expect(converted).toEqual(original)
    })
  })
})
