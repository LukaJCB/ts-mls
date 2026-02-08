import { uint16Decoder, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, encode, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { defaultExtensionTypes, isDefaultExtensionTypeValue } from "./defaultExtensionType.js"
import { externalSenderEncoder } from "./externalSender.js"
import { nodeEncoder, ratchetTreeEncoder } from "./ratchetTree.js"
import { requiredCapabilitiesEncoder } from "./requiredCapabilities.js"
import { CustomExtension, makeCustomExtension } from "./customExtension.js"
import {
  ExtensionApplicationId,
  LeafNodeExtension,
  leafNodeExtensionDecoder,
  leafNodeExtensionEncoder,
} from "./leafNodeExtension.js"
import { ExtensionRatchetTree, ExtensionExternalPub, GroupInfoExtension, groupInfoExtensionDecoder } from "./groupInfoExtension.js"
import {
  ExtensionRequiredCapabilities,
  ExtensionExternalSenders,
  GroupContextExtension,
  groupContextExtensionDecoder,
  extensionEqual,
  extensionsEqual,
  extensionsSupportedByCapabilities,
} from "./groupContextExtension.js"

/** @public */
export type DefaultExtension =
  | ExtensionApplicationId
  | ExtensionRatchetTree
  | ExtensionRequiredCapabilities
  | ExtensionExternalPub
  | ExtensionExternalSenders

/** @public */
export type Extension = DefaultExtension | CustomExtension

export { CustomExtension, makeCustomExtension }

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
    } else if (e.extensionType === defaultExtensionTypes.ratchet_tree) {
      // console.log(nodeEncoder)
      return [e.extensionType, encode(ratchetTreeEncoder, e.extensionData)]
    }
    return [e.extensionType, e.extensionData] as const
  } else return [e.extensionType, e.extensionData] as const
})

export const customExtensionDecoder: Decoder<CustomExtension> = mapDecoders(
  [uint16Decoder, varLenDataDecoder],
  (extensionType, extensionData) => ({ extensionType, extensionData }) as CustomExtension,
)

export {
  ExtensionApplicationId,
  LeafNodeExtension,
  leafNodeExtensionDecoder,
  leafNodeExtensionEncoder,
  ExtensionRatchetTree,
  ExtensionExternalPub,
  GroupInfoExtension,
  groupInfoExtensionDecoder,
  ExtensionRequiredCapabilities,
  ExtensionExternalSenders,
  GroupContextExtension,
  groupContextExtensionDecoder,
  extensionEqual,
  extensionsEqual,
  extensionsSupportedByCapabilities,
}
