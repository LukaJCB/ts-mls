import { decodeUint64, decodeUint8, encodeUint64, encodeUint8 } from "../../src/codec/number"
import { decodeOptional, encodeOptional } from "../../src/codec/optional"
import { randomBytes } from "@noble/hashes/utils.js"
import { Decoder } from "../../src/codec/tlsDecoder"
import { Encoder } from "../../src/codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "../../src/codec/variableLength"

test("optional codec should return single 0 byte", () => {
  const e = encodeOptional(encodeUint8)(undefined)
  expect(e).toStrictEqual(new Uint8Array([0]))
  const e2 = encodeOptional(encodeUint64)(undefined)
  expect(e2).toStrictEqual(new Uint8Array([0]))
  const e3 = encodeOptional(encodeVarLenData)(undefined)
  expect(e3).toStrictEqual(new Uint8Array([0]))
})

test("optional codec roundtrip uint8: 255", () => {
  optionalRoundTrip(255, encodeUint8, decodeUint8)
})

test("optional codec roundtrip uint64: 394245935729", () => {
  optionalRoundTrip(394245935729n, encodeUint64, decodeUint64)
})

test("optional codec roundtrip uint64: 394245935729", () => {
  optionalRoundTrip(394245935729n, encodeUint64, decodeUint64)
})

test("optional codec roundtrip randomBytes(8)", () => {
  optionalRoundTrip(randomBytes(8), encodeVarLenData, decodeVarLenData)
})

test("optional codec roundtrip randomBytes(128)", () => {
  optionalRoundTrip(randomBytes(128), encodeVarLenData, decodeVarLenData)
})

test("optional codec roundtrip randomBytes(500)", () => {
  optionalRoundTrip(randomBytes(500), encodeVarLenData, decodeVarLenData)
})

function optionalRoundTrip<T>(t: T, enc: Encoder<T>, dec: Decoder<T>) {
  const encodedOptional = encodeOptional(enc)(t)
  const encoded = enc(t)

  expect(encoded.byteLength).toBe(encodedOptional.byteLength - 1)

  const decodedOptional = decodeOptional(dec)(encodedOptional, 0)

  expect(decodedOptional?.[0]).toStrictEqual(t)

  const encodedNone = encodeOptional(enc)(undefined)

  const decodedNone = decodeOptional(dec)(encodedNone, 0)

  expect(decodedNone).toBeDefined()
  expect(decodedNone?.[0]).toBeUndefined()
}
