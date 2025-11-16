import { decodeOptional, encOptional } from "./codec/optional.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapEncs, Enc } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, encVarLenData, encVarLenType } from "./codec/variableLength.js"
import { decodePskId, encodePskId, PreSharedKeyID } from "./presharedkey.js"

export interface GroupSecrets {
  joinerSecret: Uint8Array
  pathSecret: Uint8Array | undefined
  psks: PreSharedKeyID[]
}

export const encodeGroupSecrets: Enc<GroupSecrets> = contramapEncs(
  [encVarLenData, encOptional(encVarLenData), encVarLenType(encodePskId)],
  (gs) => [gs.joinerSecret, gs.pathSecret, gs.psks] as const,
)

export const decodeGroupSecrets: Decoder<GroupSecrets> = mapDecoders(
  [decodeVarLenData, decodeOptional(decodeVarLenData), decodeVarLenType(decodePskId)],
  (joinerSecret, pathSecret, psks) => ({ joinerSecret, pathSecret, psks }),
)
