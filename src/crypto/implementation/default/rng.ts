import { Rng } from "../../rng.js"

export const defaultRng: Rng = {
  randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n))
  },
}
