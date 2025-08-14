import { decodeUint16, encodeUint16 } from "./codec/number"
import { Decoder, mapDecoders, orDecoder } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import {
  decodeDefaultExtensionType,
  encodeDefaultExtensionType,
  DefaultExtensionTypeName,
  defaultExtensionTypes,
} from "./defaultExtensionType"
import { constantTimeEqual } from "./util/constantTimeCompare"

export type ExtensionType = DefaultExtensionTypeName | number

export const encodeExtensionType: Encoder<ExtensionType> = (t) =>
  typeof t === "number" ? encodeUint16(t) : encodeDefaultExtensionType(t)

export const decodeExtensionType: Decoder<ExtensionType> = orDecoder(decodeDefaultExtensionType, decodeUint16)

export interface Extension {
  extensionType: ExtensionType
  extensionData: Uint8Array
}

export const encodeExtension: Encoder<Extension> = contramapEncoders(
  [encodeExtensionType, encodeVarLenData],
  (e) => [e.extensionType, e.extensionData] as const,
)

export const decodeExtension: Decoder<Extension> = mapDecoders(
  [decodeExtensionType, decodeVarLenData],
  (extensionType, extensionData) => ({ extensionType, extensionData }),
)

export function extensionEqual(a: Extension, b: Extension): boolean {
  return a.extensionType === b.extensionType && constantTimeEqual(a.extensionData, b.extensionData)
}

export function extensionsEqual(a: Extension[], b: Extension[]): boolean {
  if (a.length !== b.length) return false
  return a.every((val, i) => extensionEqual(val, b[i]!))
}

export function extensionsSupportedByCapabilities(
  requiredExtensions: Extension[],
  capabilities: { extensions: number[] },
): boolean {
  return requiredExtensions
    .filter((ex) => !isDefaultExtension(ex.extensionType))
    .every((ex) => capabilities.extensions.includes(extensionTypeToNumber(ex.extensionType)))
}

function isDefaultExtension(t: ExtensionType): boolean {
  return typeof t !== "number"
}

export function extensionTypeToNumber(t: ExtensionType): number {
  return typeof t === "number" ? t : defaultExtensionTypes[t]
}
