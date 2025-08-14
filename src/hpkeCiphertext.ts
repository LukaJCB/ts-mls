import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder"
import { encodeVarLenData, decodeVarLenData } from "./codec/variableLength"

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
