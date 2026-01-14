import { decodeUint64, decodeUint8, uint64Encoder, uint8Encoder } from "../../src/codec/number.js"
import { decodeOptional, optionalEncoder } from "../../src/codec/optional.js"
import { randomBytes } from "@noble/hashes/utils.js"
import { Decoder } from "../../src/codec/tlsDecoder.js"
import { BufferEncoder, encode } from "../../src/codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "../../src/codec/variableLength.js"

test("optional codec should return single 0 byte", () => {
  const e = encode(optionalEncoder(uint8Encoder), undefined)
  expect(e).toStrictEqual(new Uint8Array([0]))
  const e2 = encode(optionalEncoder(uint64Encoder), undefined)
  expect(e2).toStrictEqual(new Uint8Array([0]))
  const e3 = encode(optionalEncoder(varLenDataEncoder), undefined)
  expect(e3).toStrictEqual(new Uint8Array([0]))
})

test("optional codec roundtrip uint8: 255", () => {
  optionalRoundTrip(255, uint8Encoder, decodeUint8)
})

test("optional codec roundtrip uint64: 394245935729", () => {
  optionalRoundTrip(394245935729n, uint64Encoder, decodeUint64)
})

test("optional codec roundtrip uint64: 394245935729", () => {
  optionalRoundTrip(394245935729n, uint64Encoder, decodeUint64)
})

test("optional codec roundtrip randomBytes(8)", () => {
  optionalRoundTrip(randomBytes(8), varLenDataEncoder, decodeVarLenData)
})

test("optional codec roundtrip randomBytes(128)", () => {
  optionalRoundTrip(randomBytes(128), varLenDataEncoder, decodeVarLenData)
})

test("optional codec roundtrip randomBytes(500)", () => {
  optionalRoundTrip(randomBytes(500), varLenDataEncoder, decodeVarLenData)
})

function optionalRoundTrip<T>(t: T, enc: BufferEncoder<T>, dec: Decoder<T>) {
  const encodedOptional = encode(optionalEncoder(enc), t)
  const encoded = encode(enc, t)

  expect(encoded.byteLength).toBe(encodedOptional.byteLength - 1)

  const decodedOptional = decodeOptional(dec)(encodedOptional, 0)

  expect(decodedOptional?.[0]).toStrictEqual(t)

  const encodedNone = encode(optionalEncoder(enc), undefined)

  const decodedNone = decodeOptional(dec)(encodedNone, 0)

  expect(decodedNone).toBeDefined()
  expect(decodedNone?.[0]).toBeUndefined()
}
