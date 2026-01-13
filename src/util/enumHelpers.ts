export function numberToEnum<S extends string, N extends number>(t: Record<S, N>): (n: number) => N | undefined {
  return (n) => (Object.values(t).includes(n) ? (n as N) : undefined)
}
