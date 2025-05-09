function log2(x: number): number {
  if (x === 0) return 0
  let k = 0
  while (x >> k > 0) {
    k++
  }
  return k - 1
}

function level(nodeIndex: number): number {
  if ((nodeIndex & 0x01) === 0) return 0

  let k = 0
  while (((nodeIndex >> k) & 0x01) === 1) {
    k++
  }
  return k
}

export function isLeaf(nodeIndex: number) {
  return nodeIndex % 2 == 0
}

export function leafToNodeIndex(leafIndex: number) {
  return leafIndex * 2
}

export function nodeToLeafIndex(nodeIndex: number) {
  return nodeIndex / 2
}

export function leafWidth(nodeWidth: number): number {
  return nodeWidth == 0 ? 0 : (nodeWidth - 1) / 2 + 1
}

export function nodeWidth(leafWidth: number): number {
  return leafWidth === 0 ? 0 : 2 * (leafWidth - 1) + 1
}

export function rootFromNodeWidth(nodeWidth: number): number {
  return (1 << log2(nodeWidth)) - 1
}

export function root(leafWidth: number): number {
  const w = nodeWidth(leafWidth)
  return rootFromNodeWidth(w)
}

export function left(nodeIndex: number): number {
  const k = level(nodeIndex)
  if (k === 0) throw new Error("leaf node has no children")
  return nodeIndex ^ (0x01 << (k - 1))
}

export function leftOrLeaf(nodeIndex: number): number | undefined {
  const k = level(nodeIndex)
  if (k === 0) return undefined
  return nodeIndex ^ (0x01 << (k - 1))
}

export function right(nodeIndex: number): number {
  const k = level(nodeIndex)
  if (k === 0) throw new Error("leaf node has no children")
  return nodeIndex ^ (0x03 << (k - 1))
}

export function parent(nodeIndex: number, leafWidth: number): number {
  if (nodeIndex === root(leafWidth)) throw new Error("root node has no parent")
  const k = level(nodeIndex)
  const b = (nodeIndex >> (k + 1)) & 0x01
  return (nodeIndex | (1 << k)) ^ (b << (k + 1))
}

export function sibling(x: number, n: number): number {
  const p = parent(x, n)
  return x < p ? right(p) : left(p)
}

export function directPath(nodeIndex: number, leafWidth: number): number[] {
  const r = root(leafWidth)
  if (nodeIndex === r) return []

  const d: number[] = []
  while (nodeIndex !== r) {
    nodeIndex = parent(nodeIndex, leafWidth)
    d.push(nodeIndex)
  }
  return d
}

export function copath(nodeIndex: number, leafWidth: number): number[] {
  if (nodeIndex === root(leafWidth)) return []

  const d = directPath(nodeIndex, leafWidth)
  d.unshift(nodeIndex)
  d.pop()

  return d.map((y) => sibling(y, leafWidth))
}

export function commonAncestorSemantic(x: number, y: number, n: number): number {
  const dx = new Set<number>([x, ...directPath(x, n)])
  const dy = new Set<number>([y, ...directPath(y, n)])

  const intersection = Array.from(dx).filter((z) => dy.has(z))
  if (intersection.length === 0) {
    throw new Error("failed to find common ancestor")
  }

  return intersection.reduce((min, current) => {
    return level(current) < level(min) ? current : min
  })
}

export function commonAncestorDirect(x: number, y: number, _n: number): number {
  const lx = level(x) + 1
  const ly = level(y) + 1

  if (lx <= ly && x >> ly === y >> ly) return y
  if (ly <= lx && x >> lx === y >> lx) return x

  let xn = x
  let yn = y
  let k = 0
  while (xn !== yn) {
    xn >>= 1
    yn >>= 1
    k++
  }

  return (xn << k) + (1 << (k - 1)) - 1
}
