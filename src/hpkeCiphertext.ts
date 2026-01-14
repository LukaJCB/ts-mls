import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { Encoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { varLenDataEncoder, varLenDataDecoder } from "./codec/variableLength.js"

/** @public */
export interface HPKECiphertext {
  kemOutput: Uint8Array
  ciphertext: Uint8Array
}

export const hpkeCiphertextEncoder: Encoder<HPKECiphertext> = contramapBufferEncoders(
  [varLenDataEncoder, varLenDataEncoder],
  (egs) => [egs.kemOutput, egs.ciphertext] as const,
)

export const hpkeCiphertextDecoder: Decoder<HPKECiphertext> = mapDecoders(
  [varLenDataDecoder, varLenDataDecoder],
  (kemOutput, ciphertext) => ({ kemOutput, ciphertext }),
)
