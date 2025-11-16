export type Encoder<T> = (t: T) => Uint8Array


export type Enc<T> = (t: T) => [number, (offset: number, buffer: ArrayBuffer) => void]

export function encode<T>(enc: Enc<T>): Encoder<T> {
  return (t: T) => {
    const [len, write] = enc(t)
    const buf = new ArrayBuffer(len)
    write(0, buf)
    return new Uint8Array(buf)
  }
}

export function composeEnc<T, U>(encT: Enc<T>, encU: Enc<U>): Enc<[T, U]> {
  return ([t, u]) => {
    const [lenT, writeT] = encT(t)
    const [lenU, writeU] = encU(u)

    return [lenT + lenU, (offset, buffer)=> {
      writeT(offset, buffer)
      writeU(offset + lenT, buffer)
    }]
  }
}

export function contramapEnc<T, U>(enc: Enc<T>, f: (u: U) => Readonly<T>): Enc<U> {
  return (u: U) => enc(f(u))
}


export function contramapEncs<T extends unknown[], R>(
  encoders: { [K in keyof T]: Enc<T[K]> },
  toTuple: (input: R) => T,
): Enc<R> {
  return (value: R) => {
    const values = toTuple(value)
    let totalLength = 0
    let writeTotal = (_offset: number, _buffer: ArrayBuffer) => {}
    for (let i = 0; i < encoders.length; i++){
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


export function composeEncs<T extends unknown[]>(encoders: { [K in keyof T]: Enc<T[K]> }): Enc<T> {
  return (values: T) => contramapEncs(encoders, (t) => t as T)(values)
}

export function encVoid<T>(): Enc<T> {
  return () => [0, () => {}]
}

export function contramapEncoders<T extends unknown[], R>(
  encoders: { [K in keyof T]: Encoder<T[K]> },
  toTuple: (input: R) => T,
): Encoder<R> {
  return (value: R) => {
    const values = toTuple(value)

    const encodedParts: Uint8Array[] = new Array<Uint8Array>(values.length)
    let totalLength = 0
    for (let i = 0; i < values.length; i++) {
      const encoded = encoders[i]!(values[i])
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
