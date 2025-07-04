import {
  encodeUint8,
  encodeUint16,
  decodeUint8,
  decodeUint16,
  encodeUint32,
  decodeUint32,
  encodeUint64,
  decodeUint64,
} from "../../src/codec/number"

test("encode and decode works for uint8: 0", () => {
  uint8RoundTrip(0)
})

test("encode and decode works for uint8: 16", () => {
  uint8RoundTrip(16)
})

test("encode and decode works for uint8: 255", () => {
  uint8RoundTrip(255)
})

test("encode and decode works for uint16: 0", () => {
  uint16RoundTrip(0)
})

test("encode and decode works for uint16: 256", () => {
  uint16RoundTrip(256)
})

test("encode and decode works for uint16: 65535", () => {
  uint16RoundTrip(65535)
})

test("encode and decode works for uint32: 0", () => {
  uint32RoundTrip(0)
})

test("encode and decode works for uint32: 65536", () => {
  uint32RoundTrip(65536)
})

test("encode and decode works for uint32: 4294967295", () => {
  uint32RoundTrip(4294967295)
})

test("encode and decode works for uint64: 0", () => {
  uint64RoundTrip(0n)
})

test("encode and decode works for uint64: 4294967296", () => {
  uint64RoundTrip(4294967295n)
})

test("encode and decode works for uint64: 18446744073709551615", () => {
  uint64RoundTrip(18446744073709551615n)
})

test("decodeUint8 fails for an array that's empty", () => {
  expect(decodeUint8(new Uint8Array([]), 0)).toBeUndefined
})

test("decodeUint16 fails for an array that's too small", () => {
  expect(decodeUint16(new Uint8Array([0]), 0)).toBeUndefined
})

test("decodeUint32 fails for an array that's too small", () => {
  expect(decodeUint32(new Uint8Array([0, 1]), 0)).toBeUndefined
})

test("decodeUint64 fails for an array that's too small", () => {
  expect(decodeUint64(new Uint8Array([0, 1, 2, 3]), 0)).toBeUndefined
})

function uint8RoundTrip(num: number) {
  const encoded = encodeUint8(num)

  const decoded = decodeUint8(encoded, 0)

  expect(decoded?.[0]).toBe(num)
  expect(decoded?.[1]).toBe(1)
}

function uint16RoundTrip(num: number) {
  const encoded = encodeUint16(num)

  const decoded = decodeUint16(encoded, 0)

  expect(decoded?.[0]).toBe(num)
  expect(decoded?.[1]).toBe(2)
}

function uint32RoundTrip(num: number) {
  const encoded = encodeUint32(num)

  const decoded = decodeUint32(encoded, 0)

  expect(decoded?.[0]).toBe(num)
  expect(decoded?.[1]).toBe(4)
}

function uint64RoundTrip(num: bigint) {
  const encoded = encodeUint64(num)

  const decoded = decodeUint64(encoded, 0)

  expect(decoded?.[0]).toEqual(num)
  expect(decoded?.[1]).toBe(8)
}
