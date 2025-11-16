import { decodeUint8 } from "./number.js"
import { Decoder } from "./tlsDecoder.js"
import { BufferEncoder } from "./tlsEncoder.js"

export function optionalEncoder<T>(encodeT: BufferEncoder<T>): BufferEncoder<T | undefined> {
  return (t) => {
    if (t) {
      const [len, write] = encodeT(t)
      return [
        len + 1,
        (offset, buffer) => {
          const view = new DataView(buffer)
          view.setUint8(offset, 0x1)
          write(offset + 1, buffer)
        },
      ]
    } else {
      return [
        1,
        (offset, buffer) => {
          const view = new DataView(buffer)
          view.setUint8(offset, 0x0)
        },
      ]
    }
  }
}

export function decodeOptional<T>(decodeT: Decoder<T>): Decoder<T | undefined> {
  return (b, offset) => {
    const presenceOctet = decodeUint8(b, offset)?.[0]
    if (presenceOctet == 1) {
      const result = decodeT(b, offset + 1)
      return result === undefined ? undefined : [result[0], result[1] + 1]
    } else {
      return [undefined, 1]
    }
  }
}
