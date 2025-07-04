import { Decoder } from "./tlsDecoder"
import { Encoder } from "./tlsEncoder"

export const encodeUint8: Encoder<number> = (n) => {
  const buffer = new ArrayBuffer(1)
  const view = new DataView(buffer)
  view.setUint8(0, n)
  return new Uint8Array(buffer)
}

export const decodeUint8: Decoder<number> = (b, offset) => {
  const value = b.at(offset)
  return value !== undefined ? [value, 1] : undefined
}

export const encodeUint16: Encoder<number> = (n) => {
  const buffer = new ArrayBuffer(2)
  const view = new DataView(buffer)
  view.setUint16(0, n)
  return new Uint8Array(buffer)
}

export const decodeUint16: Decoder<number> = (b, offset) => {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  try {
    return [view.getUint16(offset), 2]
  } catch (e) {
    return undefined
  }
}

export const encodeUint32: Encoder<number> = (n) => {
  const buffer = new ArrayBuffer(4)
  const view = new DataView(buffer)
  view.setUint32(0, n)
  return new Uint8Array(buffer)
}

export const decodeUint32: Decoder<number> = (b, offset) => {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  try {
    return [view.getUint32(offset), 4]
  } catch (e) {
    return undefined
  }
}

export const encodeUint64: Encoder<bigint> = (n) => {
  const buffer = new ArrayBuffer(8)
  const view = new DataView(buffer)
  view.setBigUint64(0, n)
  return new Uint8Array(buffer)
}

export const decodeUint64: Decoder<bigint> = (b, offset) => {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  try {
    return [view.getBigUint64(offset), 8]
  } catch (e) {
    return undefined
  }
}
