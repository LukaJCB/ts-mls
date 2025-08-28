import { Rng } from "../../rng"

export const defaultRng: Rng = {
  randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n))
  },
}
