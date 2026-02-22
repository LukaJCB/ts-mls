import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { ValidationError } from "./mlsError.js"
import { PskId, updatePskSecret } from "./presharedkey.js"

export interface PskIndex {
  findPsk(preSharedKeyId: PskId): Uint8Array | undefined
}

export async function accumulatePskSecret(
  groupedPsk: PskId[],
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
  zeroes: Uint8Array,
): Promise<[Uint8Array, PskId[]]> {
  return groupedPsk.reduce<Promise<[Uint8Array, PskId[]]>>(
    async (acc, cur, index) => {
      const [previousSecret, ids] = await acc
      const psk = pskSearch.findPsk(cur)
      if (psk === undefined) throw new ValidationError("Could not find pskId referenced in proposal")
      const pskSecret = await updatePskSecret(previousSecret, cur, psk, index, groupedPsk.length, cs)
      return [pskSecret, [...ids, cur]]
    },
    Promise.resolve([zeroes, []]),
  )
}
