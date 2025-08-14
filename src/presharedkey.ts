import { decodeUint16, decodeUint64, decodeUint8, encodeUint16, encodeUint64, encodeUint8 } from "./codec/number"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { expandWithLabel } from "./crypto/kdf"

import { enumNumberToKey } from "./util/enumHelpers"

export const pskTypes = {
  external: 1,
  resumption: 2,
} as const

export type PSKTypeName = keyof typeof pskTypes
export type PSKType = (typeof pskTypes)[PSKTypeName]

export const encodePskType: Encoder<PSKTypeName> = contramapEncoder(encodeUint8, (t) => pskTypes[t])
export const decodePskType: Decoder<PSKTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(pskTypes))

const resumptionPSKUsages = {
  application: 1,
  reinit: 2,
  branch: 3,
} as const

export type ResumptionPSKUsageName = keyof typeof resumptionPSKUsages
export type ResumptionPSKUsage = (typeof resumptionPSKUsages)[ResumptionPSKUsageName]

export const encodeResumptionPSKUsage: Encoder<ResumptionPSKUsageName> = contramapEncoder(
  encodeUint8,
  (u) => resumptionPSKUsages[u],
)

export const decodeResumptionPSKUsage: Decoder<ResumptionPSKUsageName> = mapDecoderOption(
  decodeUint8,
  enumNumberToKey(resumptionPSKUsages),
)

export interface PSKInfoExternal {
  psktype: "external"
  pskId: Uint8Array
}
export interface PSKInfoResumption {
  psktype: "resumption"
  usage: ResumptionPSKUsageName
  pskGroupId: Uint8Array
  pskEpoch: bigint
}
export type PSKInfo = PSKInfoExternal | PSKInfoResumption

const encodePskInfoExternal: Encoder<PSKInfoExternal> = contramapEncoders(
  [encodePskType, encodeVarLenData],
  (i) => [i.psktype, i.pskId] as const,
)

const encodePskInfoResumption: Encoder<PSKInfoResumption> = contramapEncoders(
  [encodePskType, encodeResumptionPSKUsage, encodeVarLenData, encodeUint64],
  (info) => [info.psktype, info.usage, info.pskGroupId, info.pskEpoch] as const,
)

const decodePskInfoResumption = mapDecoders(
  [decodeResumptionPSKUsage, decodeVarLenData, decodeUint64],
  (usage, pskGroupId, pskEpoch) => {
    return { usage, pskGroupId, pskEpoch }
  },
)

export const encodePskInfo: Encoder<PSKInfo> = (info) => {
  switch (info.psktype) {
    case "external":
      return encodePskInfoExternal(info)
    case "resumption":
      return encodePskInfoResumption(info)
  }
}

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

type PSKNonce = { pskNonce: Uint8Array }

export type PreSharedKeyID = PSKInfo & PSKNonce

export const encodePskId: Encoder<PreSharedKeyID> = contramapEncoders(
  [encodePskInfo, encodeVarLenData],
  (pskid) => [pskid, pskid.pskNonce] as const,
)

export const decodePskId: Decoder<PreSharedKeyID> = mapDecoders(
  [decodePskInfo, decodeVarLenData],
  (info, pskNonce) => ({ ...info, pskNonce }),
)

type PSKLabel = {
  id: PreSharedKeyID
  index: number
  count: number
}

export const encodePskLabel: Encoder<PSKLabel> = contramapEncoders(
  [encodePskId, encodeUint16, encodeUint16],
  (label) => [label.id, label.index, label.count] as const,
)

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
      encodePskLabel({ id: pskId, index, count }),
      impl.kdf.size,
      impl.kdf,
    ),
    secret,
  )
}
