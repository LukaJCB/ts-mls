import { CodecError } from "../mlsError.js"
import { base64ToBytes, bytesToBase64 } from "../util/byteArray.js"
import { uint64Decoder, uint64Encoder } from "./number.js"
import { Decoder, mapDecoder, mapDecoders } from "./tlsDecoder.js"
import { Encoder, contramapBufferEncoder, contramapBufferEncoders } from "./tlsEncoder.js"

export const varLenDataEncoder: Encoder<Uint8Array> = (data) => {
  const [len, write] = lengthEncoder(data.length)

  return [
    len + data.length,
    (offset, buffer) => {
      write(offset, buffer)
      const view = new Uint8Array(buffer)
      view.set(data, offset + len)
    },
  ]
}

export function lengthEncoder(len: number): [number, (offset: number, buffer: ArrayBuffer) => void] {
  if (len < 64) {
    return [
      1,
      (offset, buffer) => {
        // 1-byte length: 00xxxxxx
        const view = new Uint8Array(buffer)
        view[offset] = len & 0b00111111
      },
    ]
  } else if (len < 16384) {
    return [
      2,
      (offset, buffer) => {
        // 2-byte length: 01xxxxxx xxxxxxxx
        const view = new Uint8Array(buffer)
        view[offset] = ((len >> 8) & 0b00111111) | 0b01000000
        view[offset + 1] = len & 0xff
      },
    ]
  } else if (len < 0x40000000) {
    return [
      4,
      (offset, buffer) => {
        // 4-byte length: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        const view = new Uint8Array(buffer)
        view[offset] = ((len >> 24) & 0b00111111) | 0b10000000
        view[offset + 1] = (len >> 16) & 0xff
        view[offset + 2] = (len >> 8) & 0xff
        view[offset + 3] = len & 0xff
      },
    ]
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

export const varLenDataDecoder: Decoder<Uint8Array> = (buf, offset) => {
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

export function varLenTypeEncoder<T>(enc: Encoder<T>): Encoder<T[]> {
  return (data) => {
    let totalLength = 0
    let writeTotal = (_offset: number, _buffer: ArrayBuffer) => {}
    for (let i = 0; i < data.length; i++) {
      const [len, write] = enc(data[i]!)
      const oldFunc = writeTotal
      const currentLen = totalLength
      writeTotal = (offset: number, buffer: ArrayBuffer) => {
        oldFunc(offset, buffer)
        write(offset + currentLen, buffer)
      }
      totalLength += len
    }
    const [headerLength, writeLength] = lengthEncoder(totalLength)
    return [
      headerLength + totalLength,
      (offset, buffer) => {
        writeLength(offset, buffer)
        writeTotal(offset + headerLength, buffer)
      },
    ]
  }
}

export function varLenTypeDecoder<T>(dec: Decoder<T>): Decoder<T[]> {
  return (b, offset) => {
    const d = varLenDataDecoder(b, offset)
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

export function base64RecordEncoder<V>(valueEncoder: Encoder<V>): Encoder<Record<string, V>> {
  const entryEncoder = contramapBufferEncoders(
    [contramapBufferEncoder(varLenDataEncoder, base64ToBytes), valueEncoder],
    ([key, value]: [string, V]) => [key, value] as const,
  )

  return contramapBufferEncoders([varLenTypeEncoder(entryEncoder)], (record) => [Object.entries(record)] as const)
}

export function base64RecordDecoder<V>(valueDecoder: Decoder<V>): Decoder<Record<string, V>> {
  return mapDecoder(
    varLenTypeDecoder(
      mapDecoders([mapDecoder(varLenDataDecoder, bytesToBase64), valueDecoder], (key, value) => [key, value] as const),
    ),
    (entries) => {
      const record: Record<string, V> = {}
      for (const [key, value] of entries) {
        record[key] = value
      }
      return record
    },
  )
}

export function numberRecordEncoder<V>(
  numberEncoder: Encoder<number>,
  valueEncoder: Encoder<V>,
): Encoder<Record<number, V>> {
  const entryEncoder = contramapBufferEncoders(
    [numberEncoder, valueEncoder],
    ([key, value]: [number, V]) => [key, value] as const,
  )

  return contramapBufferEncoder(varLenTypeEncoder(entryEncoder), (record) =>
    Object.entries(record).map(([key, value]) => [Number(key), value] as [number, V]),
  )
}

export function numberRecordDecoder<V>(
  numberDecoder: Decoder<number>,
  valueDecoder: Decoder<V>,
): Decoder<Record<number, V>> {
  return mapDecoder(
    varLenTypeDecoder(mapDecoders([numberDecoder, valueDecoder], (key, value) => [key, value] as const)),
    (entries) => {
      const record: Record<number, V> = {}
      for (const [key, value] of entries) {
        record[key] = value
      }
      return record
    },
  )
}
export function bigintMapEncoder<V>(valueEncoder: Encoder<V>): Encoder<Map<bigint, V>> {
  const entryEncoder = contramapBufferEncoders(
    [uint64Encoder, valueEncoder],
    ([key, value]: [bigint, V]) => [key, value] as const,
  )

  return contramapBufferEncoder(varLenTypeEncoder(entryEncoder), (map) => Array.from(map.entries()))
}

export function bigintMapDecoder<V>(valueDecoder: Decoder<V>): Decoder<Map<bigint, V>> {
  return mapDecoder(
    varLenTypeDecoder(mapDecoders([uint64Decoder, valueDecoder], (key, value) => [key, value] as const)),
    (entries) => new Map(entries),
  )
}
