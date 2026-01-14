/** @public */
export type Encoder<T> = (t: T) => [number, (offset: number, buffer: ArrayBuffer) => void]

/** @public */
export function encode<T>(enc: Encoder<T>, t: T): Uint8Array {
  const [len, write] = enc(t)
  const buf = new ArrayBuffer(len)
  write(0, buf)
  return new Uint8Array(buf)
}

export function contramapBufferEncoder<T, U>(enc: Encoder<T>, f: (u: U) => Readonly<T>): Encoder<U> {
  return (u: U) => enc(f(u))
}

export function contramapBufferEncoders<T extends unknown[], R>(
  encoders: { [K in keyof T]: Encoder<T[K]> },
  toTuple: (input: R) => T,
): Encoder<R> {
  return (value: R) => {
    const values = toTuple(value)
    let totalLength = 0
    let writeTotal = (_offset: number, _buffer: ArrayBuffer) => {}
    for (let i = 0; i < encoders.length; i++) {
      const [len, write] = encoders[i]!(values[i])
      const oldFunc = writeTotal
      const currentLen = totalLength
      writeTotal = (offset: number, buffer: ArrayBuffer) => {
        oldFunc(offset, buffer)
        write(offset + currentLen, buffer)
      }
      totalLength += len
    }
    return [totalLength, writeTotal]
  }
}

export function composeBufferEncoders<T extends unknown[]>(encoders: {
  [K in keyof T]: Encoder<T[K]>
}): Encoder<T> {
  return (values: T) => contramapBufferEncoders(encoders, (t) => t as T)(values)
}

export const encVoid: [number, (offset: number, buffer: ArrayBuffer) => void] = [0, () => {}]
