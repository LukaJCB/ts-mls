export type Encoder<T> = (t: T) => Uint8Array

export function contramapEncoders<T extends unknown[], R>(
  encoders: { [K in keyof T]: Encoder<T[K]> },
  toTuple: (input: R) => T,
): Encoder<R> {
  return (value: R) => {
    const values = toTuple(value)

    const encodedParts: Uint8Array[] = new Array(values.length)
    let totalLength = 0
    for (let i = 0; i < values.length; i++) {
      const encoded = encoders[i]!(values[i]!)
      totalLength += encoded.byteLength
      encodedParts[i] = encoded
    }

    const result = new Uint8Array(totalLength)
    let offset = 0
    for (const arr of encodedParts) {
      result.set(arr, offset)
      offset += arr.length
    }

    return result
  }
}

export function composeEncoders<T extends unknown[]>(encoders: { [K in keyof T]: Encoder<T[K]> }): Encoder<T> {
  return (values: T) => contramapEncoders(encoders, (t) => t as T)(values)
}

export function contramapEncoder<T, U>(enc: Encoder<T>, f: (u: U) => Readonly<T>): Encoder<U> {
  return (u: U) => enc(f(u))
}

export function encodeVoid<T>(): Encoder<T> {
  return () => new Uint8Array()
}
