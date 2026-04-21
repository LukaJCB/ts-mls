import { Decoder } from "./tlsDecoder.js"
import { Encoder, viewFor } from "./tlsEncoder.js"

export const uint8Encoder: Encoder<number> = (n) => [
  1,
  (offset, buffer) => {
    viewFor(buffer).setUint8(offset, n)
  },
]

export const uint8Decoder: Decoder<number> = (b, offset) => {
  const value = b.at(offset)
  return value !== undefined ? [value, 1] : undefined
}

export const uint16Encoder: Encoder<number> = (n) => [
  2,
  (offset, buffer) => {
    viewFor(buffer).setUint16(offset, n)
  },
]

export const uint16Decoder: Decoder<number> = (b, offset) => {
  if (offset + 2 > b.byteLength) return undefined
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  return [view.getUint16(offset), 2]
}

export const uint32Encoder: Encoder<number> = (n) => [
  4,
  (offset, buffer) => {
    viewFor(buffer).setUint32(offset, n)
  },
]

export const uint32Decoder: Decoder<number> = (b, offset) => {
  if (offset + 4 > b.byteLength) return undefined
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  return [view.getUint32(offset), 4]
}

export const uint64Encoder: Encoder<bigint> = (n) => [
  8,
  (offset, buffer) => {
    viewFor(buffer).setBigUint64(offset, n)
  },
]

export const uint64Decoder: Decoder<bigint> = (b, offset) => {
  if (offset + 8 > b.byteLength) return undefined
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  return [view.getBigUint64(offset), 8]
}
