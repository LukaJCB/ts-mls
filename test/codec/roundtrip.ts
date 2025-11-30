import { Decoder } from "../../src/codec/tlsDecoder.js"
import { Encoder } from "../../src/codec/tlsEncoder.js"

export function createRoundtripTest<T>(enc: Encoder<T>, dec: Decoder<T>): (t: T) => void {
  return (t) => {
    const encoded = enc(t)

    const decoded = dec(encoded, 0)?.[0] as T

    expect(decoded).toStrictEqual(t)
  }
}
