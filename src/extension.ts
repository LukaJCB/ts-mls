import { uint16Decoder, uint16Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { defaultExtensionTypes, isDefaultExtensionTypeValue } from "./defaultExtensionType.js"
import { UsageError } from "./mlsError.js"
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
  extensionData: Uint8Array
}

/** @public */
export interface ExtensionExternalPub {
  extensionType: typeof defaultExtensionTypes.external_pub
  extensionData: Uint8Array
}

/** @public */
export interface ExtensionExternalSenders {
  extensionType: typeof defaultExtensionTypes.external_senders
  extensionData: Uint8Array
}

/** @public */
export type GroupInfoExtension = ExtensionRatchetTree | ExtensionExternalPub | CustomExtension

/** @public */
export type GroupContextExtension = ExtensionRequiredCapabilities | ExtensionExternalSenders | CustomExtension

/** @public */
export type LeafNodeExtension = ExtensionApplicationId | CustomExtension

export type Extension =
  | ExtensionApplicationId
  | ExtensionRatchetTree
  | ExtensionRequiredCapabilities
  | ExtensionExternalPub
  | ExtensionExternalSenders
  | CustomExtension

export function makeCustomExtension(extensionType: number, extensionData: Uint8Array): CustomExtension {
  if (isDefaultExtensionTypeValue(extensionType)) {
    throw new UsageError("Cannot create custom exception with default extension type")
  }
  return { extensionType, extensionData } as CustomExtension
}

export const extensionEncoder: Encoder<Extension> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (e) => [e.extensionType, e.extensionData] as const,
)

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
      return mapDecoder(varLenDataDecoder, (extensionData) => {
        return { extensionType: defaultExtensionTypes.external_senders, extensionData: extensionData }
      })
    } else if (extensionType === defaultExtensionTypes.required_capabilities) {
      return mapDecoder(varLenDataDecoder, (extensionData) => {
        return { extensionType: defaultExtensionTypes.required_capabilities, extensionData }
      })
    } else
      return mapDecoder(varLenDataDecoder, (extensionData) => ({ extensionType, extensionData }) as CustomExtension)
  },
)

export function extensionEqual(a: GroupContextExtension, b: GroupContextExtension): boolean {
  if (a.extensionType !== b.extensionType) return false

  return constantTimeEqual(a.extensionData, b.extensionData)
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

export function decodeFully<T>(dec: Decoder<T>, b: Uint8Array): T | undefined {
  const decoded = dec(b, 0)
  if (decoded === undefined) return undefined
  const [value, len] = decoded
  return len === b.length ? value : undefined
}
