import { decodeUint16, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import {
  DefaultExtensionTypeName,
  DefaultExtensionTypeValue,
  defaultExtensionTypeValueFromName,
  isDefaultExtensionTypeValue,
} from "./defaultExtensionType.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"

/** @public */
export interface Extension {
  extensionType: number
  extensionData: Uint8Array
}

export const extensionEncoder: BufferEncoder<Extension> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (e) => [e.extensionType, e.extensionData] as const,
)

export const encodeExtension: Encoder<Extension> = encode(extensionEncoder)

export const decodeExtension: Decoder<Extension> = mapDecoders(
  [decodeUint16, decodeVarLenData],
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
    .every((ex) => capabilities.extensions.includes(ex.extensionType))
}

function isDefaultExtension(t: number): boolean {
  return isDefaultExtensionTypeValue(t)
}

export function extensionTypeValueFromName(name: DefaultExtensionTypeName): DefaultExtensionTypeValue {
  return defaultExtensionTypeValueFromName(name)
}
