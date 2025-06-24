import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { PreSharedKeyID, updatePskSecret } from "./presharedkey"
import { ProposalPSK } from "./proposal"

export interface PskIndex {
  findPsk(preSharedKeyId: PreSharedKeyID): Uint8Array | undefined
}
export const emptyPskIndex: PskIndex = {
  findPsk(_preSharedKeyId) {
    return undefined
  },
}

export async function accumulatePskSecret(
  groupedPsk: { proposal: ProposalPSK }[],
  pskSearch: PskIndex,
  cs: CiphersuiteImpl,
  zeroes: Uint8Array,
): Promise<[Uint8Array, PreSharedKeyID[]]> {
  return groupedPsk.reduce<Promise<[Uint8Array, PreSharedKeyID[]]>>(
    async (acc, cur, index) => {
      const [previousSecret, ids] = await acc
      const psk = pskSearch.findPsk(cur.proposal.psk.preSharedKeyId)
      if (psk === undefined) throw new Error("Could not find pskId referenced in proposal")
      const pskSecret = await updatePskSecret(
        previousSecret,
        cur.proposal.psk.preSharedKeyId,
        psk,
        index,
        groupedPsk.length,
        cs,
      )
      return [pskSecret, [...ids, cur.proposal.psk.preSharedKeyId]]
    },
    Promise.resolve([zeroes, []]),
  )
}
