import { uint16Decoder, uint16Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { defaultExtensionTypes } from "./defaultExtensionType.js"
import { CustomExtension } from "./customExtension.js"

/** @public */
export interface ExtensionApplicationId {
  extensionType: typeof defaultExtensionTypes.application_id
  extensionData: Uint8Array
}

/** @public */
export type LeafNodeExtension = ExtensionApplicationId | CustomExtension

export const leafNodeExtensionEncoder: Encoder<LeafNodeExtension> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (e) => [e.extensionType, e.extensionData] as const,
)

export const leafNodeExtensionDecoder: Decoder<LeafNodeExtension> = flatMapDecoder(
  uint16Decoder,
  (extensionType): Decoder<LeafNodeExtension> => {
    if (extensionType === defaultExtensionTypes.application_id) {
      return mapDecoder(varLenDataDecoder, (extensionData) => {
        return { extensionType: defaultExtensionTypes.application_id, extensionData }
      })
    }
    return mapDecoder(varLenDataDecoder, (extensionData) => ({ extensionType, extensionData }) as CustomExtension)
  },
)
