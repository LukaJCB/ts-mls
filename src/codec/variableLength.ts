import { CodecError } from "../mlsError.js"
import { Decoder } from "./tlsDecoder.js"
import { Enc, Encoder } from "./tlsEncoder.js"

export const encodeVarLenData: Encoder<Uint8Array> = (data) => {
  const lenBytes: Uint8Array = encodeLength(data.length)

  const result = new Uint8Array(lenBytes.length + data.length)
  result.set(lenBytes, 0)
  result.set(data, lenBytes.length)
  return result
}


export const encVarLenData: Enc<Uint8Array> = (data) => {
  const [len, write] = encLength(data.length)

  return [len + data.length, (offset, buffer) => {
    write(offset, buffer)
    const view = new Uint8Array(buffer)
    view.set(data, offset + len)
  }]
}

export function encodeLength(len: number): Uint8Array {
  if (len < 64) {
    // 1-byte length: 00xxxxxx
    return new Uint8Array([len & 0b00111111])
  } else if (len < 16384) {
    // 2-byte length: 01xxxxxx xxxxxxxx
    return new Uint8Array([((len >> 8) & 0b00111111) | 0b01000000, len & 0xff])
  } else if (len < 0x40000000) {
    // 4-byte length: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    return new Uint8Array([((len >> 24) & 0b00111111) | 0b10000000, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff])
  } else {
    throw new CodecError("Length too large to encode (max is 2^30 - 1)")
  }
}

export function encLength(len: number): [number, (offset: number, buffer: ArrayBuffer) => void] {
  
  if (len < 64) {
    return [1, (offset, buffer) => {
    // 1-byte length: 00xxxxxx
    const view = new DataView(buffer)
    view.setUint8(offset, len & 0b00111111)
    }]
  } else if (len < 16384) {
    return [2, (offset, buffer) => {
    // 2-byte length: 01xxxxxx xxxxxxxx
    const view = new DataView(buffer)
    view.setUint8(offset, ((len >> 8) & 0b00111111) | 0b01000000)
    view.setUint8(offset + 1, len & 0xff)
    }]
  } else if (len < 0x40000000) {
    return [4, (offset, buffer) => {
    // 4-byte length: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    const view = new DataView(buffer)
    view.setUint8(offset, ((len >> 24) & 0b00111111) | 0b10000000)
    view.setUint8(offset + 1, (len >> 16) & 0xff)
    view.setUint8(offset + 2,  (len >> 8) & 0xff)
    view.setUint8(offset + 3,  len & 0xff)
    }]
  } else {
    throw new CodecError("Length too large to encode (max is 2^30 - 1)")
  }
}

export function determineLength(data: Uint8Array, offset: number = 0): { length: number; lengthFieldSize: number } {
  if (offset >= data.length) {
    throw new CodecError("Offset beyond buffer")
  }

  const firstByte = data[offset] as number
  const prefix = firstByte >> 6

  if (prefix === 0) {
    return { length: firstByte & 0b00111111, lengthFieldSize: 1 }
  } else if (prefix === 1) {
    if (offset + 2 > data.length) throw new CodecError("Incomplete 2-byte length")
    return { length: ((firstByte & 0b00111111) << 8) | (data[offset + 1] as number), lengthFieldSize: 2 }
  } else if (prefix === 2) {
    if (offset + 4 > data.length) throw new CodecError("Incomplete 4-byte length")
    return {
      length:
        ((firstByte & 0b00111111) << 24) |
        ((data[offset + 1] as number) << 16) |
        ((data[offset + 2] as number) << 8) |
        (data[offset + 3] as number),
      lengthFieldSize: 4,
    }
  } else {
    throw new CodecError("8-byte length not supported in this implementation")
  }
}

export const decodeVarLenData: Decoder<Uint8Array> = (buf, offset) => {
  if (offset >= buf.length) {
    throw new CodecError("Offset beyond buffer")
  }

  const { length, lengthFieldSize } = determineLength(buf, offset)

  const totalBytes = lengthFieldSize + length
  if (offset + totalBytes > buf.length) {
    throw new CodecError("Data length exceeds buffer")
  }

  const data = buf.subarray(offset + lengthFieldSize, offset + totalBytes)
  return [data, totalBytes]
}

export function encodeVarLenType<T>(enc: Encoder<T>): Encoder<T[]> {
  return (data) => {
    const encodedParts = new Array<Uint8Array>(data.length)
    let dataLength = 0

    for (let i = 0; i < data.length; i++) {
      const encoded = enc(data[i]!)
      dataLength += encoded.byteLength
      encodedParts[i] = encoded
    }

    const lengthHeader: Uint8Array = encodeLength(dataLength)

    const result = new Uint8Array(lengthHeader.length + dataLength)
    result.set(lengthHeader, 0)
    let offset = lengthHeader.length

    for (const arr of encodedParts) {
      result.set(arr, offset)
      offset += arr.length
    }
    return result
  }
}

export function encVarLenType<T>(enc: Enc<T>): Enc<T[]> {
  return (data) => {
    let totalLength = 0
    let writeTotal = (_offset: number, _buffer: ArrayBuffer) => {}
    for (let i = 0; i < data.length; i++){
      const [len, write] = enc(data[i]!)
      const oldFunc = writeTotal
      const currentLen = totalLength
      writeTotal = (offset: number, buffer: ArrayBuffer) => {
        oldFunc(offset, buffer)
        write(offset + currentLen, buffer)
      }
      totalLength += len
    }
    const [headerLength, writeLength] = encLength(totalLength)
    return [headerLength + totalLength, (offset, buffer) => {
      writeLength(offset, buffer)
      writeTotal(offset + headerLength, buffer)
    }]
  }
}

export function decodeVarLenType<T>(dec: Decoder<T>): Decoder<T[]> {
  return (b, offset) => {
    const d = decodeVarLenData(b, offset)
    if (d === undefined) return

    const [totalBytes, totalLength] = d

    let cursor = 0
    const result: T[] = []

    while (cursor < totalBytes.length) {
      const item = dec(totalBytes, cursor)
      if (item === undefined) return undefined

      const [value, len] = item
      result.push(value)
      cursor += len
    }

    return [result, totalLength]
  }
}
