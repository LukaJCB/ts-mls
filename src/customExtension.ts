import { isDefaultExtensionTypeValue } from "./defaultExtensionType.js"
import { UsageError } from "./mlsError.js"

declare const __custom_extension_brand: unique symbol

/** @public */
export interface CustomExtension {
  readonly [__custom_extension_brand]: true
  extensionType: number
  extensionData: Uint8Array
}

/** @public */
export function makeCustomExtension(extension: { extensionType: number; extensionData: Uint8Array }): CustomExtension {
  if (isDefaultExtensionTypeValue(extension.extensionType)) {
    throw new UsageError("Cannot create custom exception with default extension type")
  }
  return extension as CustomExtension
}
