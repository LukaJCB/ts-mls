export function enumNumberToKey<S extends string>(t: Record<S, number>): (n: number) => S | undefined {
  return (n) => (Object.values(t).includes(n) ? (reverseMap(t)[n] as S) : undefined)
}

export function reverseMap<T extends Record<string, number>>(obj: T): Record<number, string> {
  return Object.entries(obj).reduce(
    (acc, [key, value]) => ({
      ...acc,
      [value]: key,
    }),
    {},
  )
}
export function openEnumNumberToKey<S extends string>(rec: Record<S, number>): (n: number) => S | undefined {
  return (n) => {
    const decoded = enumNumberToKey(rec)(n)
    if (decoded === undefined) return n.toString() as S
    else return decoded
  }
}

export function openEnumNumberEncoder<S extends string>(rec: Record<S, number>): (s: S) => number {
  return (s) => {
    const x = rec[s]
    if (x === undefined) return Number(s)
    else return x
  }
}
