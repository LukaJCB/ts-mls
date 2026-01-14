import { randomBytes } from "@noble/hashes/utils.js"
import {
  varLenDataDecoder,
  varLenTypeDecoder,
  determineLength,
  lengthEncoder,
  varLenDataEncoder,
  varLenTypeEncoder,
} from "../../src/codec/variableLength.js"
import { createRoundtripTest } from "./roundtrip.js"
import { BufferEncoder, encode } from "../../src/codec/tlsEncoder.js"
import { Decoder } from "../../src/codec/tlsDecoder.js"
import { uint64Decoder, uint8Decoder, uint64Encoder, uint8Encoder } from "../../src/codec/number.js"
import { optionalDecoder, optionalEncoder } from "../../src/codec/optional.js"
import { CodecError } from "../../src/mlsError.js"

test("encode and decode works for 1 random byte", () => {
  varLenRoundtrip(randomBytes(1))
})

test("encode and decode works for 2 random bytes", () => {
  varLenRoundtrip(randomBytes(2))
})

test("encode and decode works for 3 random bytes", () => {
  varLenRoundtrip(randomBytes(3))
})

test("encode and decode works for 4 random bytes", () => {
  varLenRoundtrip(randomBytes(4))
})

test("encode and decode works for 8 random bytes", () => {
  varLenRoundtrip(randomBytes(8))
})

test("encode and decode works for 16 random bytes", () => {
  varLenRoundtrip(randomBytes(16))
})

test("encode and decode works for 64 random bytes", () => {
  varLenRoundtrip(randomBytes(64))
})

test("encode and decode works for 256 random bytes", () => {
  varLenRoundtrip(randomBytes(256))
})

test("encode and decode works for 1024 random bytes", () => {
  varLenRoundtrip(randomBytes(1024))
})

test("encode and decode works for 9999 random bytes", () => {
  varLenRoundtrip(randomBytes(9999))
})

test("encode and decode works for 9999 random bytes", () => {
  varLenRoundtrip(randomBytes(9999))
})

test("encode and decode works for array of random bytes", () => {
  arrayRoundtrip(varLenDataEncoder, varLenDataDecoder, [
    randomBytes(9999),
    randomBytes(9999),
    randomBytes(9999),
    randomBytes(9999),
  ])
})

test("encode and decode works for array of uint8", () => {
  arrayRoundtrip(uint8Encoder, uint8Decoder, [1, 2, 3, 4, 5])
})

test("encode and decode works for array of uint64", () => {
  arrayRoundtrip(uint64Encoder, uint64Decoder, [1n, 2n, 3n, 4n, 5n, 18446744073709551615n])
})

test("encode and decode works for array of optional random bytes", () => {
  arrayRoundtrip(optionalEncoder(varLenDataEncoder), optionalDecoder(varLenDataDecoder), [
    randomBytes(99),
    undefined,
    randomBytes(99),
    undefined,
    undefined,
    randomBytes(99),
    randomBytes(99),
  ])
})

test("decode doesn't work if offset is too large", () => {
  expect(() => varLenDataDecoder(new Uint8Array(0), 2)).toThrow(CodecError)
})

test("determineLength doesn't work if offset is too large", () => {
  expect(() => determineLength(new Uint8Array(0), 2)).toThrow(CodecError)
})

test("determineLength doesn't work if prefix is too large", () => {
  expect(() => determineLength(encode(lengthEncoder, 50000000000), 1)).toThrow(CodecError)
})

test("determineLength doesn't work if offset is ffsd large", () => {
  expect(() => determineLength(new Uint8Array([0xff, 0xff]), 0)).toThrow(CodecError)
})

test("decode doesn't work if length is too large", () => {
  const e = encode(varLenDataEncoder, randomBytes(64))
  e[1] = 0xff
  expect(() => varLenDataDecoder(e, 0)).toThrow(CodecError)
})

test("varLenTypeDecoder doesn't work if underlying decoder doesn't work", () => {
  const brokenDecoder: Decoder<number> = () => undefined

  expect(varLenTypeDecoder(brokenDecoder)(encode(varLenDataEncoder, randomBytes(16)), 0)).toBeUndefined()
})

const varLenRoundtrip = createRoundtripTest(varLenDataEncoder, varLenDataDecoder)

function arrayRoundtrip<T>(enc: BufferEncoder<T>, dec: Decoder<T>, ts: T[]) {
  return createRoundtripTest(varLenTypeEncoder(enc), varLenTypeDecoder(dec))(ts)
}
