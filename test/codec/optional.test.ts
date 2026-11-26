import { uint64Decoder, uint8Decoder, uint64Encoder, uint8Encoder } from "../../src/codec/number.js"
import { optionalDecoder, optionalEncoder } from "../../src/codec/optional.js"
import { randomBytes } from "@noble/hashes/utils.js"
import { Decoder } from "../../src/codec/tlsDecoder.js"
import { Encoder, encode } from "../../src/codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "../../src/codec/variableLength.js"

test("optional codec should return single 0 byte", () => {
  const e = encode(optionalEncoder(uint8Encoder), undefined)
  expect(e).toStrictEqual(new Uint8Array([0]))
  const e2 = encode(optionalEncoder(uint64Encoder), undefined)
  expect(e2).toStrictEqual(new Uint8Array([0]))
  const e3 = encode(optionalEncoder(varLenDataEncoder), undefined)
  expect(e3).toStrictEqual(new Uint8Array([0]))
})

test("optional decoder rejects every presence byte other than 0 or 1", () => {
  const decoder = optionalDecoder(uint8Decoder)
  for (let presence = 2; presence <= 255; presence++) {
    expect(decoder(Uint8Array.of(presence), 0)).toBeUndefined()
    expect(decoder(Uint8Array.of(presence, 42), 0)).toBeUndefined()
  }
})

test("optional decoder rejects a missing presence byte at empty input", () => {
  expect(optionalDecoder(uint8Decoder)(Uint8Array.from([]), 0)).toBeUndefined()
})

test("optional decoder rejects a missing presence byte at the end of a nonempty input", () => {
  expect(optionalDecoder(uint8Decoder)(Uint8Array.from([0]), 1)).toBeUndefined()
})

test("optional decoder rejects a present value with a truncated payload", () => {
  expect(optionalDecoder(uint8Decoder)(Uint8Array.of(1), 0)).toBeUndefined()
  expect(optionalDecoder(uint64Decoder)(Uint8Array.of(1, 0, 0), 0)).toBeUndefined()
})

test("optional decoder respects the offset and reports the consumed length", () => {
  const decoder = optionalDecoder(uint8Decoder)
  expect(decoder(Uint8Array.of(255, 0, 99), 1)).toStrictEqual([undefined, 1])
  expect(decoder(Uint8Array.of(255, 1, 0, 99), 1)).toStrictEqual([0, 2])
})

test("optional codec roundtrip uint8: 255", () => {
  optionalRoundTrip(255, uint8Encoder, uint8Decoder)
})

test("optional codec roundtrip uint64: 394245935729", () => {
  optionalRoundTrip(394245935729n, uint64Encoder, uint64Decoder)
})

test("optional codec roundtrip uint64: 394245935729", () => {
  optionalRoundTrip(394245935729n, uint64Encoder, uint64Decoder)
})

test("optional codec roundtrip randomBytes(8)", () => {
  optionalRoundTrip(randomBytes(8), varLenDataEncoder, varLenDataDecoder)
})

test("optional codec roundtrip randomBytes(128)", () => {
  optionalRoundTrip(randomBytes(128), varLenDataEncoder, varLenDataDecoder)
})

test("optional codec roundtrip randomBytes(500)", () => {
  optionalRoundTrip(randomBytes(500), varLenDataEncoder, varLenDataDecoder)
})

function optionalRoundTrip<T>(t: T, enc: Encoder<T>, dec: Decoder<T>) {
  const encodedOptional = encode(optionalEncoder(enc), t)
  const encoded = encode(enc, t)

  expect(encoded.byteLength).toBe(encodedOptional.byteLength - 1)

  const decodedOptional = optionalDecoder(dec)(encodedOptional, 0)

  expect(decodedOptional?.[0]).toStrictEqual(t)

  const encodedNone = encode(optionalEncoder(enc), undefined)

  const decodedNone = optionalDecoder(dec)(encodedNone, 0)

  expect(decodedNone).toBeDefined()
  expect(decodedNone?.[0]).toBeUndefined()
}
