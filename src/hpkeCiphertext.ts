import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder.js"
import { encodeVarLenData, decodeVarLenData } from "./codec/variableLength.js"

export interface HPKECiphertext {
  kemOutput: Uint8Array
  ciphertext: Uint8Array
}

export const encodeHpkeCiphertext: Encoder<HPKECiphertext> = contramapEncoders(
  [encodeVarLenData, encodeVarLenData],
  (egs) => [egs.kemOutput, egs.ciphertext] as const,
)

export const decodeHpkeCiphertext: Decoder<HPKECiphertext> = mapDecoders(
  [decodeVarLenData, decodeVarLenData],
  (kemOutput, ciphertext) => ({ kemOutput, ciphertext }),
)
