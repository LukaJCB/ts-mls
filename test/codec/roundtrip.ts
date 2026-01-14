import { Decoder } from "../../src/codec/tlsDecoder.js"
import { BufferEncoder, encode } from "../../src/codec/tlsEncoder.js"

export function createRoundtripTest<T>(enc: BufferEncoder<T>, dec: Decoder<T>): (t: T) => void {
  return (t) => {
    const encoded = encode(enc, t)

    const decoded = dec(encoded, 0)?.[0] as T

    expect(decoded).toStrictEqual(t)
  }
}

export function createRoundtripTestBufferEncoder<T>(enc: BufferEncoder<T>, dec: Decoder<T>): (t: T) => void {
  return createRoundtripTest(enc, dec)
}
