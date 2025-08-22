import { Rng } from "../../rng"
import { randomBytes } from "@noble/hashes/utils"

export const rng: Rng = {
  randomBytes(n: number): Uint8Array {
    return randomBytes(n)
  },
}
