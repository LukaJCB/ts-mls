import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption, mapDecoders, orDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import {
  decodeDefaultExtensionTypeValue,
  defaultExtensionTypes,
  DefaultExtensionTypeValue,
  isDefaultExtensionTypeValue,
} from "./defaultExtensionType.js"
import { ExternalSender, externalSenderEncoder } from "./externalSender.js"
import { decodeExternalSender } from "./externalSender.js"
import { decodeRatchetTree, RatchetTree, ratchetTreeEncoder } from "./ratchetTree.js"
import { decodeRequiredCapabilities, RequiredCapabilities, requiredCapabilitiesEncoder } from "./requiredCapabilities.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"

/** @public */
export interface CustomExtension {
  extensionType: number
  extensionData: Uint8Array
}

/** @public */
export interface ExtensionApplicationId {
  extensionType: typeof defaultExtensionTypes.application_id
  extensionData: Uint8Array
}

/** @public */
export interface ExtensionRatchetTree {
  extensionType: typeof defaultExtensionTypes.ratchet_tree
  extensionData: RatchetTree
}

/** @public */
export interface ExtensionRequiredCapabilities {
  extensionType: typeof defaultExtensionTypes.required_capabilities
  extensionData: RequiredCapabilities
}

/** @public */
export interface ExtensionExternalPub {
  extensionType: typeof defaultExtensionTypes.external_pub
  extensionData: Uint8Array
}

/** @public */
export interface ExtensionExternalSenders {
  extensionType: typeof defaultExtensionTypes.external_senders
  extensionData: ExternalSender
}

/** @public */
export type GroupInfoExtension = ExtensionRatchetTree | ExtensionExternalPub | CustomExtension

/** @public */
export type GroupContextExtension = ExtensionRequiredCapabilities | ExtensionExternalSenders | CustomExtension

/** @public */
export type LeafNodeExtension = ExtensionApplicationId | CustomExtension

type DefaultExtension =
  | ExtensionApplicationId
  | ExtensionRatchetTree
  | ExtensionRequiredCapabilities
  | ExtensionExternalPub
  | ExtensionExternalSenders

type Extension = DefaultExtension | CustomExtension

export const customExtensionEncoder: BufferEncoder<CustomExtension> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (e) => [e.extensionType, e.extensionData] as const,
)

export const decodeCustomExtension: Decoder<CustomExtension> = mapDecoders(
  [decodeUint16, decodeVarLenData],
  (extensionType, extensionData) => ({ extensionType, extensionData }),
)

export function extensionEqual(a: GroupContextExtension, b: GroupContextExtension): boolean {
  if (a.extensionType !== b.extensionType) return false

  if (!isDefaultExtension(a) && !isDefaultExtension(b)) {
    if (!(a.extensionData instanceof Uint8Array) || !(b.extensionData instanceof Uint8Array)) return false
    return constantTimeEqual(a.extensionData, b.extensionData)
  } else if (isDefaultExtension(a) && isDefaultExtension(b)) {

    if (
      a.extensionType === defaultExtensionTypes.required_capabilities &&
      b.extensionType === defaultExtensionTypes.required_capabilities
    ) {
      return requiredCapabilitiesEqual(a.extensionData, b.extensionData)
    }

    //todo compare without encoding?
    if (a.extensionType === defaultExtensionTypes.external_senders && b.extensionType === defaultExtensionTypes.external_senders) {
      return constantTimeEqual(
        encode(externalSenderEncoder, a.extensionData),
        encode(externalSenderEncoder, b.extensionData),
      )
    }
  }
  return false

}

function requiredCapabilitiesEqual(a: RequiredCapabilities, b: RequiredCapabilities): boolean {
  return (
    numbersEqualAsSet(a.extensionTypes, b.extensionTypes) &&
    numbersEqualAsSet(a.proposalTypes, b.proposalTypes) &&
    numbersEqualAsSet(a.credentialTypes, b.credentialTypes)
  )
}

function numbersEqualAsSet(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false
  const aSorted = [...a].sort((x, y) => x - y)
  const bSorted = [...b].sort((x, y) => x - y)
  return aSorted.every((val, i) => val === bSorted[i])
}

export function extensionsEqual(a: GroupContextExtension[], b: GroupContextExtension[]): boolean {
  if (a.length !== b.length) return false
  return a.every((val, i) => extensionEqual(val, b[i]!))
}

export function extensionsSupportedByCapabilities(
  requiredExtensions: Extension[],
  capabilities: { extensions: number[] },
): boolean {
  return requiredExtensions
    .filter((ex) => !isDefaultExtensionTypeValue(ex.extensionType))
    .every((ex) => capabilities.extensions.includes(ex.extensionType))
}

function isDefaultExtension(t: Extension): t is DefaultExtension {
  return isDefaultExtensionTypeValue(t.extensionType)
}

export const extensionEncoder: BufferEncoder<Extension> = (e) => {
  if (!isDefaultExtension(e)) return customExtensionEncoder(e)
  switch (e.extensionType) {
    case defaultExtensionTypes.application_id:
      return contramapBufferEncoders(
        [uint16Encoder, varLenDataEncoder],
        (e: ExtensionApplicationId) => [e.extensionType, e.extensionData] as const,
      )(e)
    case defaultExtensionTypes.ratchet_tree:
      return contramapBufferEncoders(
        [uint16Encoder, ratchetTreeEncoder],
        (e: ExtensionRatchetTree) => [e.extensionType, e.extensionData] as const,
      )(e)
    case defaultExtensionTypes.required_capabilities:
      return contramapBufferEncoders(
        [uint16Encoder, requiredCapabilitiesEncoder],
        (e: ExtensionRequiredCapabilities) => [e.extensionType, e.extensionData] as const,
      )(e)
    case defaultExtensionTypes.external_pub:
      return contramapBufferEncoders(
        [uint16Encoder, varLenDataEncoder],
        (e: ExtensionExternalPub) => [e.extensionType, e.extensionData] as const,
      )(e)
    case defaultExtensionTypes.external_senders:
      return contramapBufferEncoders(
        [uint16Encoder, externalSenderEncoder],
        (e: ExtensionExternalSenders) => [e.extensionType, e.extensionData] as const,
      )(e)
  }
}


function decodeFully<T>(dec: Decoder<T>, b: Uint8Array): T | undefined {
  const decoded = dec(b, 0)
  if (decoded === undefined) return undefined
  const [value, len] = decoded
  return len === b.length ? value : undefined
}



function decodeDefaultExtension(extensionType: DefaultExtensionTypeValue): Decoder<Extension> {
  return mapDecoderOption(decodeVarLenData, (extensionData): Extension | undefined => {
    switch (extensionType) {
      case defaultExtensionTypes.application_id:
        return { extensionType: defaultExtensionTypes.application_id, extensionData }
      case defaultExtensionTypes.external_pub:
        return { extensionType: defaultExtensionTypes.external_pub, extensionData }
      case defaultExtensionTypes.ratchet_tree: {
        const tree = decodeFully(decodeRatchetTree, extensionData)
        return tree === undefined ? undefined : { extensionType: defaultExtensionTypes.ratchet_tree, extensionData: tree }
      }
      case defaultExtensionTypes.required_capabilities: {
        const caps = decodeFully(decodeRequiredCapabilities, extensionData)
        return caps === undefined
          ? undefined
          : { extensionType: defaultExtensionTypes.required_capabilities, extensionData: caps }
      }
      case defaultExtensionTypes.external_senders: {
        const sender = decodeFully(decodeExternalSender, extensionData)
        return sender === undefined
          ? undefined
          : { extensionType: defaultExtensionTypes.external_senders, extensionData: sender }
      }
    }
  })
}

const decodeNonDefaultExtensionTypeValue: Decoder<number> = mapDecoderOption(decodeUint16, (n) =>
  isDefaultExtensionTypeValue(n) ? undefined : n,
)

function decodeCustomExtensionData(extensionType: number): Decoder<CustomExtension> {
  return mapDecoder(decodeVarLenData, (extensionData) => ({ extensionType, extensionData }))
}

export const decodeExtension: Decoder<Extension> = orDecoder(
  flatMapDecoder(decodeDefaultExtensionTypeValue, (extensionType) => decodeDefaultExtension(extensionType)),
  flatMapDecoder(decodeNonDefaultExtensionTypeValue, (extensionType) => decodeCustomExtensionData(extensionType)),
)

export const leafNodeExtensionDecoder: Decoder<LeafNodeExtension> = flatMapDecoder(decodeUint16, (extensionType) => {
  if (extensionType === defaultExtensionTypes.application_id) {
    return mapDecoder(decodeVarLenData, (extensionData) => {
      return { extensionType: defaultExtensionTypes.application_id, extensionData }
    }
  )} else return decodeCustomExtensionData(extensionType)
})

export const groupInfoExtensionDecoder: Decoder<GroupInfoExtension> = flatMapDecoder(decodeUint16, (extensionType): Decoder<GroupInfoExtension> => {
  if (extensionType === defaultExtensionTypes.external_pub) {
    return mapDecoder(decodeVarLenData, (extensionData) => {
      return { extensionType: defaultExtensionTypes.external_pub, extensionData }
    }
  )} else if (extensionType === defaultExtensionTypes.ratchet_tree) {
    return mapDecoder(decodeRatchetTree, (extensionData) => {
      
      return { extensionType: defaultExtensionTypes.ratchet_tree, extensionData }
    }
  )} else  return decodeCustomExtensionData(extensionType)
})

export const groupContextExtensionDecoder: Decoder<GroupContextExtension> = flatMapDecoder(decodeUint16, (extensionType): Decoder<GroupContextExtension> => {
  if (extensionType === defaultExtensionTypes.external_senders) {
    return mapDecoder(decodeExternalSender, (extensionData) => {
      return { extensionType: defaultExtensionTypes.external_senders, extensionData: extensionData }
    }
  )} else if (extensionType === defaultExtensionTypes.required_capabilities) {
    return mapDecoder(decodeRequiredCapabilities, (extensionData) => {
      return { extensionType: defaultExtensionTypes.required_capabilities, extensionData }
    }
  )} else  return decodeCustomExtensionData(extensionType)
})

