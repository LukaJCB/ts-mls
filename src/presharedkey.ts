import { decodeUint16, decodeUint64, decodeUint8, uint16Encoder, uint64Encoder, uint8Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { expandWithLabel } from "./crypto/kdf.js"

import { enumNumberParse, enumNumberToKey } from "./util/enumHelpers.js"

export const pskTypes = {
  external: 1,
  resumption: 2,
} as const

export type PSKTypeName = keyof typeof pskTypes
export type PSKType = (typeof pskTypes)[PSKTypeName]

export const pskTypeEncoder: BufferEncoder<PSKTypeName> = contramapBufferEncoder(uint8Encoder, (t) => pskTypes[t])

export const encodePskType: Encoder<PSKTypeName> = encode(pskTypeEncoder)
export const decodePskType: Decoder<PSKTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(pskTypes))

/** @public */
export const resumptionPSKUsages = {
  application: 1,
  reinit: 2,
  branch: 3,
} as const

/** @public */
export type ResumptionPSKUsageName = keyof typeof resumptionPSKUsages
/** @public */
export type ResumptionPSKUsageValue = (typeof resumptionPSKUsages)[ResumptionPSKUsageName]

export const resumptionPSKUsageEncoder: BufferEncoder<ResumptionPSKUsageValue> = uint8Encoder

export const encodeResumptionPSKUsage: Encoder<ResumptionPSKUsageValue> = encode(resumptionPSKUsageEncoder)

export const decodeResumptionPSKUsage: Decoder<ResumptionPSKUsageValue> = mapDecoderOption(
  decodeUint8,
  enumNumberParse(resumptionPSKUsages),
)

/** @public */
export interface PSKInfoExternal {
  psktype: "external"
  pskId: Uint8Array
}
/** @public */
export interface PSKInfoResumption {
  psktype: "resumption"
  usage: ResumptionPSKUsageValue
  pskGroupId: Uint8Array
  pskEpoch: bigint
}
/** @public */
export type PSKInfo = PSKInfoExternal | PSKInfoResumption

const encodePskInfoExternal: BufferEncoder<PSKInfoExternal> = contramapBufferEncoders(
  [pskTypeEncoder, varLenDataEncoder],
  (i) => [i.psktype, i.pskId] as const,
)

const encodePskInfoResumption: BufferEncoder<PSKInfoResumption> = contramapBufferEncoders(
  [pskTypeEncoder, resumptionPSKUsageEncoder, varLenDataEncoder, uint64Encoder],
  (info) => [info.psktype, info.usage, info.pskGroupId, info.pskEpoch] as const,
)

const decodePskInfoResumption = mapDecoders(
  [decodeResumptionPSKUsage, decodeVarLenData, decodeUint64],
  (usage, pskGroupId, pskEpoch) => {
    return { usage, pskGroupId, pskEpoch }
  },
)

export const pskInfoEncoder: BufferEncoder<PSKInfo> = (info) => {
  switch (info.psktype) {
    case "external":
      return encodePskInfoExternal(info)
    case "resumption":
      return encodePskInfoResumption(info)
  }
}

export const encodePskInfo: Encoder<PSKInfo> = encode(pskInfoEncoder)

export const decodePskInfo: Decoder<PSKInfo> = flatMapDecoder(decodePskType, (psktype): Decoder<PSKInfo> => {
  switch (psktype) {
    case "external":
      return mapDecoder(decodeVarLenData, (pskId) => ({
        psktype,
        pskId,
      }))
    case "resumption":
      return mapDecoder(decodePskInfoResumption, (resumption) => ({
        psktype,
        ...resumption,
      }))
  }
})

/** @public */
export type PSKNonce = { pskNonce: Uint8Array }

/** @public */
export type PreSharedKeyID = PSKInfo & PSKNonce

export const pskIdEncoder: BufferEncoder<PreSharedKeyID> = contramapBufferEncoders(
  [pskInfoEncoder, varLenDataEncoder],
  (pskid) => [pskid, pskid.pskNonce] as const,
)

export const encodePskId: Encoder<PreSharedKeyID> = encode(pskIdEncoder)

export const decodePskId: Decoder<PreSharedKeyID> = mapDecoders(
  [decodePskInfo, decodeVarLenData],
  (info, pskNonce) => ({ ...info, pskNonce }),
)

type PSKLabel = {
  id: PreSharedKeyID
  index: number
  count: number
}

export const pskLabelEncoder: BufferEncoder<PSKLabel> = contramapBufferEncoders(
  [pskIdEncoder, uint16Encoder, uint16Encoder],
  (label) => [label.id, label.index, label.count] as const,
)

export const encodePskLabel: Encoder<PSKLabel> = encode(pskLabelEncoder)

export const decodePskLabel: Decoder<PSKLabel> = mapDecoders(
  [decodePskId, decodeUint16, decodeUint16],
  (id, index, count) => ({ id, index, count }),
)

export type PreSharedKeyIdExternal = PSKInfoExternal & PSKNonce
export type PreSharedKeyIdResumption = PSKInfoResumption & PSKNonce

export async function computePskSecret(psks: [PreSharedKeyID, Uint8Array][], impl: CiphersuiteImpl) {
  const zeroes: Uint8Array = new Uint8Array(impl.kdf.size)

  return psks.reduce(
    async (acc, [curId, curPsk], index) => updatePskSecret(await acc, curId, curPsk, index, psks.length, impl),
    Promise.resolve(zeroes),
  )
}

export async function updatePskSecret(
  secret: Uint8Array,
  pskId: PreSharedKeyID,
  psk: Uint8Array,
  index: number,
  count: number,
  impl: CiphersuiteImpl,
) {
  const zeroes: Uint8Array = new Uint8Array(impl.kdf.size)
  return impl.kdf.extract(
    await expandWithLabel(
      await impl.kdf.extract(zeroes, psk),
      "derived psk",
      encode(pskLabelEncoder)({ id: pskId, index, count }),
      impl.kdf.size,
      impl.kdf,
    ),
    secret,
  )
}
