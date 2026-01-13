import {
  uint16Decoder,
  uint64Decoder,
  uint8Decoder,
  uint16Encoder,
  uint64Encoder,
  uint8Encoder,
} from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { expandWithLabel } from "./crypto/kdf.js"

import { numberToEnum } from "./util/enumHelpers.js"

/** @public */
export const pskTypes = {
  external: 1,
  resumption: 2,
} as const
/** @public */
export type PSKTypeName = keyof typeof pskTypes
/** @public */
export type PSKTypeValue = (typeof pskTypes)[PSKTypeName]

export const pskTypeEncoder: BufferEncoder<PSKTypeValue> = uint8Encoder
export const pskTypeDecoder: Decoder<PSKTypeValue> = mapDecoderOption(uint8Decoder, numberToEnum(pskTypes))

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

export const resumptionPSKUsageDecoder: Decoder<ResumptionPSKUsageValue> = mapDecoderOption(
  uint8Decoder,
  numberToEnum(resumptionPSKUsages),
)

/** @public */
export interface PSKInfoExternal {
  psktype: typeof pskTypes.external
  pskId: Uint8Array
}
/** @public */
export interface PSKInfoResumption {
  psktype: typeof pskTypes.resumption
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

const pskInfoResumptionDecoder = mapDecoders(
  [resumptionPSKUsageDecoder, varLenDataDecoder, uint64Decoder],
  (usage, pskGroupId, pskEpoch) => {
    return { usage, pskGroupId, pskEpoch }
  },
)

export const pskInfoEncoder: BufferEncoder<PSKInfo> = (info) => {
  switch (info.psktype) {
    case pskTypes.external:
      return encodePskInfoExternal(info)
    case pskTypes.resumption:
      return encodePskInfoResumption(info)
  }
}

export const pskInfoDecoder: Decoder<PSKInfo> = flatMapDecoder(pskTypeDecoder, (psktype): Decoder<PSKInfo> => {
  switch (psktype) {
    case pskTypes.external:
      return mapDecoder(varLenDataDecoder, (pskId) => ({
        psktype,
        pskId,
      }))
    case pskTypes.resumption:
      return mapDecoder(pskInfoResumptionDecoder, (resumption) => ({
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

export const pskIdDecoder: Decoder<PreSharedKeyID> = mapDecoders(
  [pskInfoDecoder, varLenDataDecoder],
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

export const pskLabelDecoder: Decoder<PSKLabel> = mapDecoders(
  [pskIdDecoder, uint16Decoder, uint16Decoder],
  (id, index, count) => ({ id, index, count }),
)

export type PreSharedKeyIdExternal = PSKInfoExternal & PSKNonce

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
      encode(pskLabelEncoder, { id: pskId, index, count }),
      impl.kdf.size,
      impl.kdf,
    ),
    secret,
  )
}
