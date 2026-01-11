import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoders, orDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import {
  decodeDefaultExtensionType,
  defaultExtensionTypeEncoder,
  DefaultExtensionTypeName,
  defaultExtensionTypes,
} from "./defaultExtensionType.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"

/** @public */
export type ExtensionType = DefaultExtensionTypeName | number

export const extensionTypeEncoder: BufferEncoder<ExtensionType> = (t) =>
  typeof t === "number" ? uint16Encoder(t) : defaultExtensionTypeEncoder(t)

export const encodeExtensionType: Encoder<ExtensionType> = encode(extensionTypeEncoder)

export const decodeExtensionType: Decoder<ExtensionType> = orDecoder(decodeDefaultExtensionType, decodeUint16)

/** @public */
export interface Extension {
  extensionType: ExtensionType
  extensionData: Uint8Array
}

export const extensionEncoder: BufferEncoder<Extension> = contramapBufferEncoders(
  [extensionTypeEncoder, varLenDataEncoder],
  (e) => [e.extensionType, e.extensionData] as const,
)

export const encodeExtension: Encoder<Extension> = encode(extensionEncoder)

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
