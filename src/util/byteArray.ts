/** @public */
export function bytesToArrayBuffer(b: Uint8Array): ArrayBuffer {
  if (b.buffer instanceof ArrayBuffer) {
    if (b.byteOffset === 0 && b.byteLength === b.buffer.byteLength) {
      return b.buffer
    }
    return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)
  } else {
    const ab = new ArrayBuffer(b.byteLength)
    const arr = new Uint8Array(ab)
    arr.set(b, 0)
    return ab
  }
}
/** @public */
export function toBufferSource(b: Uint8Array): BufferSource {
  if (b.buffer instanceof ArrayBuffer) return b as Uint8Array<ArrayBuffer>
  const ab = new ArrayBuffer(b.byteLength)
  const arr = new Uint8Array(ab)
  arr.set(b, 0)
  return ab
}

/** @public */
export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64")
  } else {
    let binary = ""
    bytes.forEach((b) => (binary += String.fromCharCode(b)))
    return globalThis.btoa(binary)
  }
}

/** @public */
export function base64ToBytes(base64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return Uint8Array.from(Buffer.from(base64, "base64"))
  } else {
    const binary = globalThis.atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes
  }
}

export function concatUint8Arrays(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length)
  result.set(a, 0)
  result.set(b, a.length)
  return result
}

/** @public */
export function zeroOutUint8Array(buf: Uint8Array): void {
  crypto.getRandomValues(buf)
  for (let i = 0; i < buf.length; i++) {
    buf[i]! ^= buf[i]!
  }
}
