import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { defaultExtensionTypes, isDefaultExtensionTypeValue } from "./defaultExtensionType.js"
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

type DefaultExtension =
  | ExtensionApplicationId
  | ExtensionRatchetTree
  | ExtensionRequiredCapabilities
  | ExtensionExternalPub
  | ExtensionExternalSenders

export type Extension = DefaultExtension | CustomExtension

export const extensionEncoder: BufferEncoder<Extension> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (e) => [e.extensionType, e.extensionData] as const,
)

export const decodeExtension: Decoder<Extension> = mapDecoders(
  [decodeUint16, decodeVarLenData],
  (extensionType, extensionData) => ({ extensionType, extensionData }),
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
