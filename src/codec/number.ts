import { Decoder } from "./tlsDecoder.js"
import { Enc, encode, Encoder } from "./tlsEncoder.js"


export const encUint8: Enc<number> = (n) =>  [1, (offset, buffer) => {
  const view = new DataView(buffer)
  view.setUint8(offset, n)
}]

export const encodeUint8: Encoder<number> = encode(encUint8)

export const decodeUint8: Decoder<number> = (b, offset) => {
  const value = b.at(offset)
  return value !== undefined ? [value, 1] : undefined
}


export const encUint16: Enc<number> = (n) =>  [2, (offset, buffer) => {
  const view = new DataView(buffer)
  view.setUint16(offset, n)
}]


export const encodeUint16: Encoder<number> =  encode(encUint16)

export const decodeUint16: Decoder<number> = (b, offset) => {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  try {
    return [view.getUint16(offset), 2]
  } catch (e) {
    return undefined
  }
}



export const encUint32: Enc<number> = (n) =>  [4, (offset, buffer) => {
  const view = new DataView(buffer)
  view.setUint32(offset, n)
}]

export const encodeUint32: Encoder<number> = encode(encUint32)

export const decodeUint32: Decoder<number> = (b, offset) => {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  try {
    return [view.getUint32(offset), 4]
  } catch (e) {
    return undefined
  }
}


export const encUint64: Enc<bigint> = (n) =>  [8, (offset, buffer) => {
  const view = new DataView(buffer)
  view.setBigUint64(offset, n)
}]

export const encodeUint64: Encoder<bigint> = encode(encUint64)

export const decodeUint64: Decoder<bigint> = (b, offset) => {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  try {
    return [view.getBigUint64(offset), 8]
  } catch (e) {
    return undefined
  }
}
