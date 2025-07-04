export type Decoder<T> = (b: Uint8Array, offset: number) => [T, number] | undefined

export function mapDecoder<T, U>(dec: Decoder<T>, f: (t: T) => U): Decoder<U> {
  return (b, offset) => {
    const x = dec(b, offset)
    if (x !== undefined) {
      const [t, l] = x
      return [f(t), l]
    }
  }
}

export function mapDecodersOption<T extends unknown[], R>(
  decoders: { [K in keyof T]: Decoder<T[K]> },
  f: (...args: T) => R | undefined,
): Decoder<R> {
  return (b, offset) => {
    const initial = mapDecoders(decoders, f)(b, offset)
    if (initial === undefined) return undefined
    else {
      const [r, len] = initial
      return r !== undefined ? [r, len] : undefined
    }
  }
}

export function mapDecoders<T extends unknown[], R>(
  decoders: { [K in keyof T]: Decoder<T[K]> },
  f: (...args: T) => R,
): Decoder<R> {
  return (b, offset) => {
    const result = decoders.reduce<
      | {
          values: unknown[]
          offset: number
          totalLength: number
        }
      | undefined
    >(
      (acc, decoder) => {
        if (!acc) return undefined

        const decoded = decoder(b, acc.offset)
        if (!decoded) return undefined

        const [value, length] = decoded
        return {
          values: [...acc.values, value],
          offset: acc.offset + length,
          totalLength: acc.totalLength + length,
        }
      },
      { values: [], offset, totalLength: 0 },
    )

    if (!result) return
    return [f(...(result.values as T)), result.totalLength]
  }
}

export function mapDecoderOption<T, U>(dec: Decoder<T>, f: (t: T) => U | undefined): Decoder<U> {
  return (b, offset) => {
    const x = dec(b, offset)
    if (x !== undefined) {
      const [t, l] = x
      const u = f(t)
      return u !== undefined ? [u, l] : undefined
    }
  }
}

export function flatMapDecoder<T, U>(dec: Decoder<T>, f: (t: T) => Decoder<U>): Decoder<U> {
  return flatMapDecoderAndMap(dec, f, (_t, u) => u)
}

export function orDecoder<T, U>(decT: Decoder<T>, decU: Decoder<U>): Decoder<T | U> {
  return (b, offset) => {
    const t = decT(b, offset)
    return t ? t : decU(b, offset)
  }
}

export function flatMapDecoderAndMap<T, U, V>(
  dec: Decoder<T>,
  f: (t: T) => Decoder<U>,
  g: (t: T, u: U) => V,
): Decoder<V> {
  return (b, offset) => {
    const decodedT = dec(b, offset)
    if (decodedT !== undefined) {
      const [t, len] = decodedT
      const decoderU = f(t)
      const decodedU = decoderU(b, offset + len)
      if (decodedU !== undefined) {
        const [u, len2] = decodedU
        return [g(t, u), len + len2]
      }
    }
  }
}

export function succeedDecoder<T>(t: T): Decoder<T> {
  return () => [t, 0] as const
}

export const decodeVoid: Decoder<void> = () => [undefined, 0] as const
