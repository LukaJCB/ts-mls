import { Kdf, deriveSecret } from "./crypto/kdf.js"
import { RatchetTree } from "./ratchetTree.js"
import { directPath, leafWidth, NodeIndex } from "./treemath.js"
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
  return (await derivePathSecrets(tree, nodeIndex, pathSecret, kdf)).commitSecret
}

export async function pathToRoot(
  tree: RatchetTree,
  nodeIndex: NodeIndex,
  pathSecret: Uint8Array,
  kdf: Kdf,
): Promise<PathSecrets> {
  return (await derivePathSecrets(tree, nodeIndex, pathSecret, kdf)).pathSecrets
}

export async function derivePathSecrets(
  tree: RatchetTree,
  nodeIndex: NodeIndex,
  pathSecret: Uint8Array,
  kdf: Kdf,
): Promise<{ pathSecrets: PathSecrets; commitSecret: Uint8Array }> {
  const pathSecrets = { [nodeIndex]: pathSecret }
  let lastPathSecret = pathSecret
  // RFC 9420 Section 7.5: only derive keys along the sender's filtered direct path.
  for (const ancestor of directPath(nodeIndex, leafWidth(tree.length))) {
    if (tree[ancestor] === undefined) continue
    lastPathSecret = await deriveSecret(lastPathSecret, "path", kdf)
    pathSecrets[ancestor] = lastPathSecret
  }

  // Section 12.4.2: the next secret after the last UpdatePath node is the commit secret,
  // including when the structural root is blank and absent from the filtered path.
  return { pathSecrets, commitSecret: await deriveSecret(lastPathSecret, "path", kdf) }
}
