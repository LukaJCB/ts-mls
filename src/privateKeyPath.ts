import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { deriveSecret } from "./crypto/kdf"
import { PathSecrets } from "./pathSecrets"
import { leafToNodeIndex } from "./treemath"

export interface PrivateKeyPath {
  leafIndex: number
  privateKeys: Record<number, Uint8Array>
}
/**
 * Merges PrivateKeyPaths, BEWARE, if there is a conflict, this function will prioritize the second `b` parameter
 */
export function mergePrivateKeyPaths(a: PrivateKeyPath, b: PrivateKeyPath): PrivateKeyPath {
  return { ...a, privateKeys: { ...a.privateKeys, ...b.privateKeys } }
}
export function updateLeafKey(path: PrivateKeyPath, newKey: Uint8Array): PrivateKeyPath {
  return { ...path, privateKeys: { ...path.privateKeys, [leafToNodeIndex(path.leafIndex)]: newKey } }
}

export async function toPrivateKeyPath(
  pathSecrets: PathSecrets,
  leafIndex: number,
  cs: CiphersuiteImpl,
): Promise<PrivateKeyPath> {
  const asArray: [number, Uint8Array][] = await Promise.all(
    Object.entries(pathSecrets).map(async ([nodeIndex, pathSecret]) => {
      const nodeSecret = await deriveSecret(pathSecret, "node", cs.kdf)
      const { privateKey } = await cs.hpke.deriveKeyPair(nodeSecret)

      return [Number(nodeIndex), await cs.hpke.exportPrivateKey(privateKey)] as const
    }),
  )

  const privateKeys: Record<number, Uint8Array> = Object.fromEntries(asArray)

  return { leafIndex, privateKeys }
}
