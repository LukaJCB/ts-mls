import { Rng } from "../../rng"

export const webCryptoRng: Rng = {
  randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n))
  },
}
