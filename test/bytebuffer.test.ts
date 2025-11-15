import { describe, expect } from "vitest"
import { bytesToArrayBuffer, toBufferSource } from "../src/util/byteArray"

describe("bytesToArrayBuffer", () => {
  test("works with ArrayBuffer-backed Uint8Array", () => {
    const buf = new ArrayBuffer(8)
    const arr = new Uint8Array(buf)
    arr.set([1, 2, 3, 4])

    const result = bytesToArrayBuffer(arr)
    expect(result).toBeInstanceOf(ArrayBuffer)
    expect(result.byteLength).toBe(arr.byteLength)
    expect(result).toBe(buf)
    expect(new Uint8Array(result)).toStrictEqual(arr)
  })

  test("works with SharedArrayBuffer-backed Uint8Array", () => {
    const sharedBuf = new SharedArrayBuffer(8)
    const sharedArr = new Uint8Array(sharedBuf)
    sharedArr.set([5, 6, 7, 8])

    const result = bytesToArrayBuffer(sharedArr)
    expect(result).toBeInstanceOf(ArrayBuffer)
    expect(result.byteLength).toBe(sharedArr.byteLength)
    expect(new Uint8Array(result)).toStrictEqual(sharedArr)
  })

  test("works with ArrayBuffer-backed Uint8Array subview (offset/length)", () => {
    const buf = new ArrayBuffer(8)
    const arr = new Uint8Array(buf, 2, 4)
    arr.set([11, 12, 13, 14])

    const result = bytesToArrayBuffer(arr)
    expect(result).toBeInstanceOf(ArrayBuffer)
    expect(result.byteLength).toBe(arr.byteLength)
    expect(new Uint8Array(result)).toStrictEqual(arr)
  })

  test("works with SharedArrayBuffer-backed Uint8Array subview (offset/length)", () => {
    const sharedBuf = new SharedArrayBuffer(8)
    const sharedArr = new Uint8Array(sharedBuf, 2, 4)
    sharedArr.set([21, 22, 23, 24])

    const result = bytesToArrayBuffer(sharedArr)
    expect(result).toBeInstanceOf(ArrayBuffer)
    expect(result.byteLength).toBe(sharedArr.byteLength)
    expect(new Uint8Array(result)).toStrictEqual(sharedArr)
  })
})

describe("toBufferSource", () => {
  test("works with ArrayBuffer-backed Uint8Array", () => {
    const buf = new ArrayBuffer(4)
    const arr = new Uint8Array(buf)
    arr.set([1, 2, 3, 4])

    const result = toBufferSource(arr)
    expect(result).toBeInstanceOf(Uint8Array)
    expect(result).toBe(arr)
  })

  test("works with SharedArrayBuffer-backed Uint8Array", () => {
    const sharedBuf = new SharedArrayBuffer(4)
    const sharedArr = new Uint8Array(sharedBuf)
    sharedArr.set([9, 10, 11, 12])

    const result = toBufferSource(sharedArr)
    expect(result).toBeInstanceOf(ArrayBuffer)
    expect(new Uint8Array(result as ArrayBuffer)).toStrictEqual(sharedArr)
  })

  test("works with ArrayBuffer-backed Uint8Array subview (offset/length)", () => {
    const buf = new ArrayBuffer(8)
    const arr = new Uint8Array(buf, 2, 4)
    arr.set([31, 32, 33, 34])

    const result = toBufferSource(arr)
    expect(result).toBeInstanceOf(Uint8Array)
    expect(result).toBe(arr)
  })

  test("works with SharedArrayBuffer-backed Uint8Array subview (offset/length)", () => {
    const sharedBuf = new SharedArrayBuffer(8)
    const sharedArr = new Uint8Array(sharedBuf, 2, 4)
    sharedArr.set([41, 42, 43, 44])

    const result = toBufferSource(sharedArr)
    expect(result).toBeInstanceOf(ArrayBuffer)
    expect(new Uint8Array(result as ArrayBuffer)).toStrictEqual(sharedArr)
  })
})
