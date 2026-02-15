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
    const lengths = new Array<number>(encoders.length)
    const writes = new Array<(offset: number, buffer: ArrayBuffer) => void>(encoders.length)
    let totalLength = 0

    for (let i = 0; i < encoders.length; i++) {
      const [len, write] = encoders[i]!(values[i])
      lengths[i] = len
      writes[i] = write
      totalLength += len
    }

    return [
      totalLength,
      (offset: number, buffer: ArrayBuffer) => {
        let cursor = offset
        for (let i = 0; i < writes.length; i++) {
          writes[i]!(cursor, buffer)
          cursor += lengths[i]!
        }
      },
    ]
  }
}

export function composeBufferEncoders<T extends unknown[]>(encoders: {
  [K in keyof T]: Encoder<T[K]>
}): Encoder<T> {
  return (values: T) => contramapBufferEncoders(encoders, (t) => t as T)(values)
}

export const encVoid: [number, (offset: number, buffer: ArrayBuffer) => void] = [0, () => {}]
