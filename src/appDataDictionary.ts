import { uint16Decoder, uint16Encoder } from "./codec/number.js"
import { decode, Decoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, encode, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder, varLenTypeDecoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CustomExtension, GroupContextExtension, makeCustomExtension } from "./extension.js"
import { UsageError, ValidationError } from "./mlsError.js"

/**
 * The `app_data_dictionary` extension type defined in draft-ietf-mls-extensions-09.
 *
 * @public
 */
export const appDataDictionaryExtensionType = 6

/**
 * A single entry in an {@link AppDataDictionary}, associating opaque application
 * data with a component id.
 *
 * @public
 */
export interface ComponentData {
  componentId: number
  data: Uint8Array
}

export const componentDataEncoder: Encoder<ComponentData> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (c) => [c.componentId, c.data] as const,
)

export const componentDataDecoder: Decoder<ComponentData> = mapDecoders(
  [uint16Decoder, varLenDataDecoder],
  (componentId, data) => ({ componentId, data }),
)

/**
 * The content of the `app_data_dictionary` extension. Entries MUST be sorted by
 * componentId and there MUST be at most one entry per componentId.
 *
 * @public
 */
export type AppDataDictionary = ComponentData[]

export const appDataDictionaryEncoder: Encoder<AppDataDictionary> = varLenTypeEncoder(componentDataEncoder)

export const appDataDictionaryDecoder: Decoder<AppDataDictionary> = mapDecoderOption(
  varLenTypeDecoder(componentDataDecoder),
  (entries) => (componentDataSortedAndUnique(entries) ? entries : undefined),
)

function componentDataSortedAndUnique(entries: ComponentData[]): boolean {
  return entries.every((e, i) => i === 0 || entries[i - 1]!.componentId < e.componentId)
}

/**
 * Creates an `app_data_dictionary` GroupContext extension carrying the given dictionary.
 * The dictionary entries must be sorted by componentId with at most one entry per componentId.
 *
 * @public
 */
export function makeAppDataDictionaryExtension(dictionary: AppDataDictionary): CustomExtension {
  if (!componentDataSortedAndUnique(dictionary))
    throw new UsageError("AppDataDictionary entries must be sorted by componentId and unique")

  return makeCustomExtension({
    extensionType: appDataDictionaryExtensionType,
    extensionData: encode(appDataDictionaryEncoder, dictionary),
  })
}

/**
 * Reads the {@link AppDataDictionary} carried in an extension list. Returns undefined
 * if no `app_data_dictionary` extension is present.
 *
 * @public
 */
export function getAppDataDictionary(extensions: GroupContextExtension[]): AppDataDictionary | undefined {
  const extension = extensions.find((e): e is CustomExtension => e.extensionType === appDataDictionaryExtensionType)
  if (extension === undefined) return undefined

  const dictionary = decode(appDataDictionaryDecoder, extension.extensionData)
  if (dictionary === undefined) throw new ValidationError("Could not decode app_data_dictionary extension")

  return dictionary
}
