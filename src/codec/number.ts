import { Decoder } from "./tlsDecoder.js"
import { BufferEncoder } from "./tlsEncoder.js"

export const uint8Encoder: BufferEncoder<number> = (n) => [
  1,
  (offset, buffer) => {
    const view = new DataView(buffer)
    view.setUint8(offset, n)
  },
]

export const uint8Decoder: Decoder<number> = (b, offset) => {
  const value = b.at(offset)
  return value !== undefined ? [value, 1] : undefined
}

export const uint16Encoder: BufferEncoder<number> = (n) => [
  2,
  (offset, buffer) => {
    const view = new DataView(buffer)
    view.setUint16(offset, n)
  },
]

export const uint16Decoder: Decoder<number> = (b, offset) => {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  try {
    return [view.getUint16(offset), 2]
  } catch (e) {
    return undefined
  }
}

export const uint32Encoder: BufferEncoder<number> = (n) => [
  4,
  (offset, buffer) => {
    const view = new DataView(buffer)
    view.setUint32(offset, n)
  },
]

export const uint32Decoder: Decoder<number> = (b, offset) => {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  try {
    return [view.getUint32(offset), 4]
  } catch (e) {
    return undefined
  }
}

export const uint64Encoder: BufferEncoder<bigint> = (n) => [
  8,
  (offset, buffer) => {
    const view = new DataView(buffer)
    view.setBigUint64(offset, n)
  },
]

export const uint64Decoder: Decoder<bigint> = (b, offset) => {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  try {
    return [view.getBigUint64(offset), 8]
  } catch (e) {
    return undefined
  }
}
