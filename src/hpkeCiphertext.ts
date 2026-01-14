import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { varLenDataEncoder, decodeVarLenData } from "./codec/variableLength.js"

/** @public */
export interface HPKECiphertext {
  kemOutput: Uint8Array
  ciphertext: Uint8Array
}

export const hpkeCiphertextEncoder: BufferEncoder<HPKECiphertext> = contramapBufferEncoders(
  [varLenDataEncoder, varLenDataEncoder],
  (egs) => [egs.kemOutput, egs.ciphertext] as const,
)

export const decodeHpkeCiphertext: Decoder<HPKECiphertext> = mapDecoders(
  [decodeVarLenData, decodeVarLenData],
  (kemOutput, ciphertext) => ({ kemOutput, ciphertext }),
)
