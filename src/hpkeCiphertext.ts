import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { Enc, contramapEncs } from "./codec/tlsEncoder.js"
import { encVarLenData, decodeVarLenData } from "./codec/variableLength.js"

export interface HPKECiphertext {
  kemOutput: Uint8Array
  ciphertext: Uint8Array
}

export const encodeHpkeCiphertext: Enc<HPKECiphertext> = contramapEncs(
  [encVarLenData, encVarLenData],
  (egs) => [egs.kemOutput, egs.ciphertext] as const,
)

export const decodeHpkeCiphertext: Decoder<HPKECiphertext> = mapDecoders(
  [decodeVarLenData, decodeVarLenData],
  (kemOutput, ciphertext) => ({ kemOutput, ciphertext }),
)
