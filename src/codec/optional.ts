import { concatUint8Arrays } from "../util/byteArray.js"
import { decodeUint8, encodeUint8 } from "./number.js"
import { Decoder } from "./tlsDecoder.js"
import { Enc, Encoder } from "./tlsEncoder.js"



export function encOptional<T>(encodeT: Enc<T>): Enc<T | undefined> {
  return (t) => {
    if (t) {
      const [len, write] = encodeT(t)
      return [len + 1, (offset, buffer) => {
        const view = new DataView(buffer)
        view.setUint8(offset, 0x1)
        write(offset + 1, buffer)
      }]
    } else {
      return [1, (offset, buffer) => {const view = new DataView(buffer)
        view.setUint8(offset, 0x0) }]
    }
  }
}

export function encodeOptional<T>(encodeT: Encoder<T>): Encoder<T | undefined> {
  return (t) => (t ? prependPresenceOctet(encodeT(t)) : new Uint8Array([0x0]))
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

function prependPresenceOctet(v: Uint8Array): Uint8Array {
  return concatUint8Arrays(encodeUint8(0x1), v)
}
