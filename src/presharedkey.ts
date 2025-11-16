import { decodeUint16, decodeUint64, decodeUint8, encUint16, encUint64, encUint8 } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapEnc, contramapEncs, Enc, encode } from "./codec/tlsEncoder.js"
import { decodeVarLenData, encVarLenData } from "./codec/variableLength.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { expandWithLabel } from "./crypto/kdf.js"

import { enumNumberToKey } from "./util/enumHelpers.js"

export const pskTypes = {
  external: 1,
  resumption: 2,
} as const

export type PSKTypeName = keyof typeof pskTypes
export type PSKType = (typeof pskTypes)[PSKTypeName]

export const encodePskType: Enc<PSKTypeName> = contramapEnc(encUint8, (t) => pskTypes[t])
export const decodePskType: Decoder<PSKTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(pskTypes))

const resumptionPSKUsages = {
  application: 1,
  reinit: 2,
  branch: 3,
} as const

export type ResumptionPSKUsageName = keyof typeof resumptionPSKUsages
export type ResumptionPSKUsage = (typeof resumptionPSKUsages)[ResumptionPSKUsageName]

export const EncesumptionPSKUsage: Enc<ResumptionPSKUsageName> = contramapEnc(
  encUint8,
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

const encodePskInfoExternal: Enc<PSKInfoExternal> = contramapEncs(
  [encodePskType, encVarLenData],
  (i) => [i.psktype, i.pskId] as const,
)

const encodePskInfoResumption: Enc<PSKInfoResumption> = contramapEncs(
  [encodePskType, EncesumptionPSKUsage, encVarLenData, encUint64],
  (info) => [info.psktype, info.usage, info.pskGroupId, info.pskEpoch] as const,
)

const decodePskInfoResumption = mapDecoders(
  [decodeResumptionPSKUsage, decodeVarLenData, decodeUint64],
  (usage, pskGroupId, pskEpoch) => {
    return { usage, pskGroupId, pskEpoch }
  },
)

export const encodePskInfo: Enc<PSKInfo> = (info) => {
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

export const encodePskId: Enc<PreSharedKeyID> = contramapEncs(
  [encodePskInfo, encVarLenData],
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

export const encodePskLabel: Enc<PSKLabel> = contramapEncs(
  [encodePskId, encUint16, encUint16],
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
      encode(encodePskLabel)({ id: pskId, index, count }),
      impl.kdf.size,
      impl.kdf,
    ),
    secret,
  )
}
