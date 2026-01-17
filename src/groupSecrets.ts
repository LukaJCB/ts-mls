import { optionalDecoder, optionalEncoder } from "./codec/optional.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenTypeDecoder, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { pskIdDecoder, pskIdEncoder, PskId } from "./presharedkey.js"

export interface GroupSecrets {
  joinerSecret: Uint8Array
  pathSecret: Uint8Array | undefined
  psks: PskId[]
}

export const groupSecretsEncoder: Encoder<GroupSecrets> = contramapBufferEncoders(
  [varLenDataEncoder, optionalEncoder(varLenDataEncoder), varLenTypeEncoder(pskIdEncoder)],
  (gs) => [gs.joinerSecret, gs.pathSecret, gs.psks] as const,
)

export const groupSecretsDecoder: Decoder<GroupSecrets> = mapDecoders(
  [varLenDataDecoder, optionalDecoder(varLenDataDecoder), varLenTypeDecoder(pskIdDecoder)],
  (joinerSecret, pathSecret, psks) => ({ joinerSecret, pathSecret, psks }),
)
