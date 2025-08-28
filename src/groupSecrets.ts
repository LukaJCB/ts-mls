import { decodeOptional, encodeOptional } from "./codec/optional.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength.js"
import { decodePskId, encodePskId, PreSharedKeyID } from "./presharedkey.js"

export interface GroupSecrets {
  joinerSecret: Uint8Array
  pathSecret: Uint8Array | undefined
  psks: PreSharedKeyID[]
}

export const encodeGroupSecrets: Encoder<GroupSecrets> = contramapEncoders(
  [encodeVarLenData, encodeOptional(encodeVarLenData), encodeVarLenType(encodePskId)],
  (gs) => [gs.joinerSecret, gs.pathSecret, gs.psks] as const,
)

export const decodeGroupSecrets: Decoder<GroupSecrets> = mapDecoders(
  [decodeVarLenData, decodeOptional(decodeVarLenData), decodeVarLenType(decodePskId)],
  (joinerSecret, pathSecret, psks) => ({ joinerSecret, pathSecret, psks }),
)
