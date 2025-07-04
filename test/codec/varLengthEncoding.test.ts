import { randomBytes } from "@noble/ciphers/webcrypto"
import {
  decodeVarLenData,
  decodeVarLenType,
  determineLength,
  encodeLength,
  encodeVarLenData,
  encodeVarLenType,
} from "../../src/codec/variableLength"
import { createRoundtripTest } from "./roundtrip"
import { Encoder } from "../../src/codec/tlsEncoder"
import { Decoder } from "../../src/codec/tlsDecoder"
import { decodeUint64, decodeUint8, encodeUint64, encodeUint8 } from "../../src/codec/number"
import { decodeOptional, encodeOptional } from "../../src/codec/optional"
import { CodecError } from "../../src/mlsError"

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
  arrayRoundtrip(encodeVarLenData, decodeVarLenData, [
    randomBytes(9999),
    randomBytes(9999),
    randomBytes(9999),
    randomBytes(9999),
  ])
})

test("encode and decode works for array of uint8", () => {
  arrayRoundtrip(encodeUint8, decodeUint8, [1, 2, 3, 4, 5])
})

test("encode and decode works for array of uint64", () => {
  arrayRoundtrip(encodeUint64, decodeUint64, [1n, 2n, 3n, 4n, 5n, 18446744073709551615n])
})

test("encode and decode works for array of optional random bytes", () => {
  arrayRoundtrip(encodeOptional(encodeVarLenData), decodeOptional(decodeVarLenData), [
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
  expect(() => decodeVarLenData(new Uint8Array(0), 2)).toThrow(CodecError)
})

test("determineLength doesn't work if offset is too large", () => {
  expect(() => determineLength(new Uint8Array(0), 2)).toThrow(CodecError)
})

test("determineLength doesn't work if prefix is too large", () => {
  expect(() => determineLength(encodeLength(50000000000), 1)).toThrow(CodecError)
})

test("determineLength doesn't work if offset is ffsd large", () => {
  expect(() => determineLength(new Uint8Array([0xff, 0xff]), 0)).toThrow(CodecError)
})

test("decode doesn't work if length is too large", () => {
  const e = encodeVarLenData(randomBytes(64))
  e[1] = 0xff
  expect(() => decodeVarLenData(e, 0)).toThrow(CodecError)
})

test("decodeVarLenType doesn't work if underlying decoder doesn't work", () => {
  const brokenDecoder: Decoder<number> = () => undefined

  expect(decodeVarLenType(brokenDecoder)(encodeVarLenData(randomBytes(16)), 0)).toBeUndefined()
})

const varLenRoundtrip = createRoundtripTest(encodeVarLenData, decodeVarLenData)

function arrayRoundtrip<T>(enc: Encoder<T>, dec: Decoder<T>, ts: T[]) {
  return createRoundtripTest(encodeVarLenType(enc), decodeVarLenType(dec))(ts)
}
