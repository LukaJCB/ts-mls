import { randomBytes } from "@noble/hashes/utils.js"
import {
  decodeUint16,
  decodeUint32,
  decodeUint8,
  uint16Encoder,
  uint32Encoder,
  uint8Encoder,
} from "../../src/codec/number.js"
import { Decoder, mapDecoders } from "../../src/codec/tlsDecoder.js"
import { BufferEncoder, composeBufferEncoders, encode } from "../../src/codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "../../src/codec/variableLength.js"
import { decodeOptional, optionalEncoder } from "../../src/codec/optional.js"

test("composite codec roundtrip [uint8(0), uint32(48948430)]", () => {
  compositeRoundTrip(0, 48948430, uint8Encoder, decodeUint8, uint32Encoder, decodeUint32)
})

test("composite codec roundtrip [uint16(256), randombytes(16)]", () => {
  compositeRoundTrip(256, randomBytes(16), uint16Encoder, decodeUint16, varLenDataEncoder, decodeVarLenData)
})

test("composite codec roundtrip [randombytes(100), randombytes(16)]", () => {
  compositeRoundTrip(
    randomBytes(100),
    randomBytes(16),
    varLenDataEncoder,
    decodeVarLenData,
    varLenDataEncoder,
    decodeVarLenData,
  )
})

test("composite codec roundtrip [randombytes(100), optional randombytes(16)]", () => {
  compositeRoundTrip(
    randomBytes(100),
    randomBytes(16),
    varLenDataEncoder,
    decodeVarLenData,
    optionalEncoder(varLenDataEncoder),
    decodeOptional(decodeVarLenData),
  )
})

test("composite codec roundtrip [randombytes(100), undefined]", () => {
  compositeRoundTrip(
    randomBytes(100),
    undefined,
    varLenDataEncoder,
    decodeVarLenData,
    optionalEncoder(varLenDataEncoder),
    decodeOptional(decodeVarLenData),
  )
})

test("composite codec roundtrip [undefined, uint8(0)]", () => {
  compositeRoundTrip(
    undefined,
    0,
    optionalEncoder(varLenDataEncoder),
    decodeOptional(decodeVarLenData),
    uint8Encoder,
    decodeUint8,
  )
})

test("composite codec roundtrip [undefined, uint16(128)]", () => {
  compositeRoundTrip(
    undefined,
    128,
    optionalEncoder(uint32Encoder),
    decodeOptional(decodeUint32),
    uint16Encoder,
    decodeUint16,
  )
})

test("composite codec roundtrip [randombytes(8), undefined, uint32(99999)]", () => {
  compositeRoundTrip3(
    randomBytes(8),
    undefined,
    99999,
    varLenDataEncoder,
    decodeVarLenData,
    optionalEncoder(uint32Encoder),
    decodeOptional(decodeUint32),
    uint32Encoder,
    decodeUint32,
  )
})

test("composite codec roundtrip [uint8(0), undefined, undefined, randomBytes(128)]", () => {
  compositeRoundTrip4(
    0,
    undefined,
    undefined,
    randomBytes(8),
    uint8Encoder,
    decodeUint8,
    optionalEncoder(uint8Encoder),
    decodeOptional(decodeUint8),
    optionalEncoder(uint32Encoder),
    decodeOptional(decodeUint32),
    varLenDataEncoder,
    decodeVarLenData,
  )
})

test("composite codec roundtrip [undefined, undefined, undefined, randomBytes(999)]", () => {
  compositeRoundTrip4(
    undefined,
    undefined,
    undefined,
    randomBytes(999),
    optionalEncoder(uint8Encoder),
    decodeOptional(decodeUint8),
    optionalEncoder(uint8Encoder),
    decodeOptional(decodeUint8),
    optionalEncoder(uint32Encoder),
    decodeOptional(decodeUint32),
    varLenDataEncoder,
    decodeVarLenData,
  )
})

test("composite codec roundtrip [randomBytes(999), randomBytes(999), undefined, randomBytes(999)]", () => {
  compositeRoundTrip4(
    randomBytes(999),
    randomBytes(999),
    undefined,
    randomBytes(999),
    varLenDataEncoder,
    decodeVarLenData,
    varLenDataEncoder,
    decodeVarLenData,
    optionalEncoder(uint32Encoder),
    decodeOptional(decodeUint32),
    varLenDataEncoder,
    decodeVarLenData,
  )
})

function compositeRoundTrip<T, U>(
  t: T,
  u: U,
  encT: BufferEncoder<T>,
  decT: Decoder<T>,
  encU: BufferEncoder<U>,
  decU: Decoder<U>,
) {
  const encoder = composeBufferEncoders([encT, encU])
  const decoder = mapDecoders([decT, decU], (t, u) => [t, u] as const)
  const encoded = encode(encoder, [t, u])

  const decoded = decoder(encoded, 0)

  expect(decoded?.[0]).toStrictEqual([t, u])
}

function compositeRoundTrip3<T, U, V>(
  t: T,
  u: U,
  v: V,
  encT: BufferEncoder<T>,
  decT: Decoder<T>,
  encU: BufferEncoder<U>,
  decU: Decoder<U>,
  encV: BufferEncoder<V>,
  decV: Decoder<V>,
) {
  const encoder = composeBufferEncoders([encT, encU, encV])
  const decoder = mapDecoders([decT, decU, decV], (t, u, v) => [t, u, v] as const)
  const encoded = encode(encoder, [t, u, v])

  const decoded = decoder(encoded, 0)

  expect(decoded?.[0]).toStrictEqual([t, u, v])
}

function compositeRoundTrip4<T, U, V, W>(
  t: T,
  u: U,
  v: V,
  w: W,
  encT: BufferEncoder<T>,
  decT: Decoder<T>,
  encU: BufferEncoder<U>,
  decU: Decoder<U>,
  encV: BufferEncoder<V>,
  decV: Decoder<V>,
  encW: BufferEncoder<W>,
  decW: Decoder<W>,
) {
  const encoder = composeBufferEncoders([encT, encU, encV, encW])
  const decoder = mapDecoders([decT, decU, decV, decW], (t, u, v, w) => [t, u, v, w] as const)
  const encoded = encode(encoder, [t, u, v, w])

  const decoded = decoder(encoded, 0)

  expect(decoded?.[0]).toStrictEqual([t, u, v, w])
}
