import { uint16Decoder, uint16Encoder } from "./codec/number.js"
import { decode, Decoder, flatMapDecoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, encode, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { defaultExtensionTypes, isDefaultExtensionTypeValue } from "./defaultExtensionType.js"
import { ExternalSender, externalSenderDecoder, externalSenderEncoder } from "./externalSender.js"
import { UsageError } from "./mlsError.js"
import {
  RequiredCapabilities,
  requiredCapabilitiesDecoder,
  requiredCapabilitiesEncoder,
} from "./requiredCapabilities.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"

declare const __custom_extension_brand: unique symbol

/** @public */
export interface CustomExtension {
  readonly [__custom_extension_brand]: true
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
  extensionData: Uint8Array
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

/** @public */
export type DefaultExtension =
  | ExtensionApplicationId
  | ExtensionRatchetTree
  | ExtensionRequiredCapabilities
  | ExtensionExternalPub
  | ExtensionExternalSenders

/** @public */
export type Extension = DefaultExtension | CustomExtension

/** @public */
export function makeCustomExtension(extension: { extensionType: number; extensionData: Uint8Array }): CustomExtension {
  if (isDefaultExtensionTypeValue(extension.extensionType)) {
    throw new UsageError("Cannot create custom exception with default extension type")
  }
  return extension as CustomExtension
}

/** @public */
export function isDefaultExtension(e: Extension): e is DefaultExtension {
  return isDefaultExtensionTypeValue(e.extensionType)
}

export const extensionEncoder: Encoder<Extension> = contramapBufferEncoders([uint16Encoder, varLenDataEncoder], (e) => {
  if (isDefaultExtension(e)) {
    if (e.extensionType === defaultExtensionTypes.required_capabilities) {
      return [e.extensionType, encode(requiredCapabilitiesEncoder, e.extensionData)]
    } else if (e.extensionType === defaultExtensionTypes.external_senders) {
      return [e.extensionType, encode(externalSenderEncoder, e.extensionData)]
    }
    return [e.extensionType, e.extensionData] as const
  } else return [e.extensionType, e.extensionData] as const
})

export const customExtensionDecoder: Decoder<CustomExtension> = mapDecoders(
  [uint16Decoder, varLenDataDecoder],
  (extensionType, extensionData) => ({ extensionType, extensionData }) as CustomExtension,
)

export const leafNodeExtensionDecoder: Decoder<LeafNodeExtension> = flatMapDecoder(
  uint16Decoder,
  (extensionType): Decoder<LeafNodeExtension> => {
    if (extensionType === defaultExtensionTypes.application_id) {
      return mapDecoder(varLenDataDecoder, (extensionData) => {
        return { extensionType: defaultExtensionTypes.application_id, extensionData }
      })
    } else
      return mapDecoder(varLenDataDecoder, (extensionData) => ({ extensionType, extensionData }) as CustomExtension)
  },
)

export const groupInfoExtensionDecoder: Decoder<GroupInfoExtension> = flatMapDecoder(
  uint16Decoder,
  (extensionType): Decoder<GroupInfoExtension> => {
    if (extensionType === defaultExtensionTypes.external_pub) {
      return mapDecoder(varLenDataDecoder, (extensionData) => {
        return { extensionType: defaultExtensionTypes.external_pub, extensionData }
      })
    } else if (extensionType === defaultExtensionTypes.ratchet_tree) {
      return mapDecoder(varLenDataDecoder, (extensionData) => {
        return { extensionType: defaultExtensionTypes.ratchet_tree, extensionData }
      })
    } else
      return mapDecoder(varLenDataDecoder, (extensionData) => ({ extensionType, extensionData }) as CustomExtension)
  },
)

export const groupContextExtensionDecoder: Decoder<GroupContextExtension> = flatMapDecoder(
  uint16Decoder,
  (extensionType): Decoder<GroupContextExtension> => {
    if (extensionType === defaultExtensionTypes.external_senders) {
      return mapDecoderOption(varLenDataDecoder, (extensionData) => {
        const res = decode(externalSenderDecoder, extensionData)
        if (res) return { extensionType: defaultExtensionTypes.external_senders, extensionData: res }
      })
    } else if (extensionType === defaultExtensionTypes.required_capabilities) {
      return mapDecoderOption(varLenDataDecoder, (extensionData) => {
        const res = decode(requiredCapabilitiesDecoder, extensionData)
        if (res) return { extensionType: defaultExtensionTypes.required_capabilities, extensionData: res }
      })
    } else
      return mapDecoder(varLenDataDecoder, (extensionData) => ({ extensionType, extensionData }) as CustomExtension)
  },
)

export function extensionEqual(a: GroupContextExtension, b: GroupContextExtension): boolean {
  if (a.extensionType !== b.extensionType) return false

  if (isDefaultExtension(a)) {
    if (a.extensionType === defaultExtensionTypes.required_capabilities) {
      return a.extensionData === b.extensionData
    } else if (
      a.extensionType === defaultExtensionTypes.external_senders &&
      b.extensionType === defaultExtensionTypes.external_senders
    ) {
      return constantTimeEqual(
        encode(externalSenderEncoder, a.extensionData),
        encode(externalSenderEncoder, b.extensionData as ExternalSender),
      )
    }
  }

  //TypeScript isn't smart enough to figure out the extensionTypes are the same
  return constantTimeEqual(a.extensionData as Uint8Array, b.extensionData as Uint8Array)
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
