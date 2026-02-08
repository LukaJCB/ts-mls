import { uint16Decoder } from "./codec/number.js"
import { decode, Decoder, flatMapDecoder, mapDecoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { encode } from "./codec/tlsEncoder.js"
import { varLenDataDecoder } from "./codec/variableLength.js"
import { defaultExtensionTypes, isDefaultExtensionTypeValue } from "./defaultExtensionType.js"
import { ExternalSender, externalSenderDecoder, externalSenderEncoder } from "./externalSender.js"
import { RequiredCapabilities, requiredCapabilitiesDecoder } from "./requiredCapabilities.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"
import { CustomExtension } from "./customExtension.js"

/** @public */
export interface ExtensionRequiredCapabilities {
  extensionType: typeof defaultExtensionTypes.required_capabilities
  extensionData: RequiredCapabilities
}

/** @public */
export interface ExtensionExternalSenders {
  extensionType: typeof defaultExtensionTypes.external_senders
  extensionData: ExternalSender
}

/** @public */
export type GroupContextExtension = ExtensionRequiredCapabilities | ExtensionExternalSenders | CustomExtension

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
    }
    return mapDecoder(varLenDataDecoder, (extensionData) => ({ extensionType, extensionData }) as CustomExtension)
  },
)

export function extensionEqual(a: GroupContextExtension, b: GroupContextExtension): boolean {
  if (a.extensionType !== b.extensionType) return false

  if (isDefaultExtensionTypeValue(a.extensionType) && isDefaultExtensionTypeValue(b.extensionType)) {
    if (a.extensionType === defaultExtensionTypes.required_capabilities) {
      return a.extensionData === b.extensionData
    } else if (
      a.extensionType === defaultExtensionTypes.external_senders &&
      b.extensionType === defaultExtensionTypes.external_senders
    ) {
      return constantTimeEqual(
        encode(externalSenderEncoder, a.extensionData),
        encode(externalSenderEncoder, b.extensionData),
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
  requiredExtensions: { extensionType: number }[],
  capabilities: { extensions: number[] },
): boolean {
  return requiredExtensions
    .filter((ex) => !isDefaultExtensionTypeValue(ex.extensionType))
    .every((ex) => capabilities.extensions.includes(ex.extensionType))
}
