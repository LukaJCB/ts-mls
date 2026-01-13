export function numberToEnum<S extends string, N extends number>(t: Record<S, N>): (n: number) => N | undefined {
  return (n) => (Object.values(t).includes(n) ? (n as N) : undefined)
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
