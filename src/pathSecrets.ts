import { Kdf, deriveSecret } from "./crypto/kdf.js"
import { InternalError } from "./mlsError.js"
import { RatchetTree, findFirstNonBlankAncestor } from "./ratchetTree.js"
import { root, leafWidth, NodeIndex } from "./treemath.js"
import { PathSecret } from "./updatePath.js"

/**
 * PathSecrets is a record with nodeIndex as keys and the path secret as values
 */

export type PathSecrets = Record<number, Uint8Array>

export function pathToPathSecrets(pathSecrets: PathSecret[]): PathSecrets {
  return pathSecrets.reduce(
    (acc, cur) => ({
      ...acc,
      [cur.nodeIndex]: cur.secret,
    }),
    {},
  )
}
export async function getCommitSecret(
  tree: RatchetTree,
  nodeIndex: NodeIndex,
  pathSecret: Uint8Array,
  kdf: Kdf,
): Promise<Uint8Array> {
  const rootIndex = root(leafWidth(tree.length))
  const path = await pathToRoot(tree, nodeIndex, pathSecret, kdf)
  const rootSecret = path[rootIndex]

  if (rootSecret === undefined) throw new InternalError("Could not find secret for root")
  return deriveSecret(rootSecret, "path", kdf)
}

export async function pathToRoot(
  tree: RatchetTree,
  nodeIndex: NodeIndex,
  pathSecret: Uint8Array,
  kdf: Kdf,
): Promise<PathSecrets> {
  const rootIndex = root(leafWidth(tree.length))
  let currentIndex = nodeIndex
  const pathSecrets = { [nodeIndex]: pathSecret }
  while (currentIndex != rootIndex) {
    const nextIndex = findFirstNonBlankAncestor(tree, currentIndex)
    const nextSecret = await deriveSecret(pathSecrets[currentIndex]!, "path", kdf)

    pathSecrets[nextIndex] = nextSecret
    currentIndex = nextIndex
  }

  return pathSecrets
}
