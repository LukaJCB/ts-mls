import { uint16Decoder } from "./codec/number.js"
import { decode, Decoder, flatMapDecoder, mapDecoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { varLenDataDecoder } from "./codec/variableLength.js"
import { defaultExtensionTypes } from "./defaultExtensionType.js"
import { CustomExtension } from "./customExtension.js"
import { RatchetTree, ratchetTreeDecoder } from "./ratchetTree.js"
import { bytesToHex } from "@noble/ciphers/utils.js"

/** @public */
export interface ExtensionRatchetTree {
  extensionType: typeof defaultExtensionTypes.ratchet_tree
  extensionData: RatchetTree
}

/** @public */
export interface ExtensionExternalPub {
  extensionType: typeof defaultExtensionTypes.external_pub
  extensionData: Uint8Array
}

/** @public */
export type GroupInfoExtension = ExtensionRatchetTree | ExtensionExternalPub | CustomExtension

export const groupInfoExtensionDecoder: Decoder<GroupInfoExtension> = flatMapDecoder(
  uint16Decoder,
  (extensionType): Decoder<GroupInfoExtension> => {
    if (extensionType === defaultExtensionTypes.external_pub) {
      return mapDecoder(varLenDataDecoder, (extensionData) => {
        return { extensionType: defaultExtensionTypes.external_pub, extensionData }
      })
    } else if (extensionType === defaultExtensionTypes.ratchet_tree) {
      return mapDecoderOption(varLenDataDecoder, (extensionData) => {
        const res = decode(ratchetTreeDecoder, extensionData)
        if (!res) {
          console.log(bytesToHex(extensionData))
          return undefined
        }
        if (res) return { extensionType: defaultExtensionTypes.ratchet_tree, extensionData: res }
      })
    }
    return mapDecoder(varLenDataDecoder, (extensionData) => ({ extensionType, extensionData }) as CustomExtension)
  },
)
