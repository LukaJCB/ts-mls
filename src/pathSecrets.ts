import { PathSecret } from "./updatePath"

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
