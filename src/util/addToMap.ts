export function addToMap<V>(map: Map<bigint, V>, k: bigint, v: V): Map<bigint, V> {
  const copy = new Map(map)
  copy.set(k, v)
  return copy
}
