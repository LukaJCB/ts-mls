import { decodeUint8, encUint8 } from "./codec/number.js"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapEnc, Enc } from "./codec/tlsEncoder.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

const contentTypes = {
  application: 1,
  proposal: 2,
  commit: 3,
} as const

export type ContentTypeName = keyof typeof contentTypes
export type ContentTypeValue = (typeof contentTypes)[ContentTypeName]

export const encodeContentType: Enc<ContentTypeName> = contramapEnc(encUint8, (t) => contentTypes[t])

export const decodeContentType: Decoder<ContentTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(contentTypes))
