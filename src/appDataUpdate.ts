import { uint16Decoder, uint16Encoder, uint8Decoder, uint8Encoder } from "./codec/number.js"
import { Decoder, failDecoder, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import {
  appDataDictionaryExtensionType,
  getAppDataDictionary,
  makeAppDataDictionaryExtension,
} from "./appDataDictionary.js"
import { GroupContextExtension } from "./extension.js"
import { ValidationError } from "./mlsError.js"

/**
 * The `app_data_update` proposal type defined in draft-ietf-mls-extensions-09.
 *
 * @public
 */
export const appDataUpdateProposalType = 8

/**
 * The AppDataUpdateOperation values defined in draft-ietf-mls-extensions-09.
 *
 * @public
 */
export const appDataUpdateOperations = {
  update: 1,
  remove: 2,
} as const

/** @public */
export type AppDataUpdateOperationName = keyof typeof appDataUpdateOperations

/**
 * The content of an `app_data_update` proposal (draft-ietf-mls-extensions-09):
 * either replaces the application data for a component or removes the component's
 * entry from the `app_data_dictionary` GroupContext extension.
 *
 * @public
 */
export type AppDataUpdate =
  | { componentId: number; operation: "update"; update: Uint8Array }
  | { componentId: number; operation: "remove" }

const appDataUpdateUpdateEncoder: Encoder<{ componentId: number; update: Uint8Array }> = contramapBufferEncoders(
  [uint16Encoder, uint8Encoder, varLenDataEncoder],
  (u) => [u.componentId, appDataUpdateOperations.update, u.update] as const,
)

const appDataUpdateRemoveEncoder: Encoder<{ componentId: number }> = contramapBufferEncoders(
  [uint16Encoder, uint8Encoder],
  (u) => [u.componentId, appDataUpdateOperations.remove] as const,
)

export const appDataUpdateEncoder: Encoder<AppDataUpdate> = (u) =>
  u.operation === "update" ? appDataUpdateUpdateEncoder(u) : appDataUpdateRemoveEncoder(u)

export const appDataUpdateDecoder: Decoder<AppDataUpdate> = flatMapDecoder(
  mapDecoders([uint16Decoder, uint8Decoder], (componentId, operation) => ({ componentId, operation })),
  ({ componentId, operation }): Decoder<AppDataUpdate> => {
    switch (operation) {
      case appDataUpdateOperations.update:
        return mapDecoder(varLenDataDecoder, (update) => ({ componentId, operation: "update", update }))
      case appDataUpdateOperations.remove:
        return succeedDecoder({ componentId, operation: "remove" })
      default:
        return failDecoder()
    }
  },
)

/**
 * The application logic that interprets the update payloads of `app_data_update`
 * proposals for a component (draft-ietf-mls-extensions-09 Section 4.7).
 *
 * Receives the componentId, the current data stored for the component (or undefined
 * if no entry exists) and the update payloads for the component in commit order.
 * Returns the new data to store for the component, or undefined if the application
 * considers the updates invalid, which invalidates the whole proposal list.
 *
 * @public
 */
export type AppDataUpdateCallback = (
  componentId: number,
  currentData: Uint8Array | undefined,
  updates: Uint8Array[],
) => Uint8Array | undefined

/**
 * The default {@link AppDataUpdateCallback}: each update payload fully replaces the
 * component's data, so the last update for a component wins.
 *
 * @public
 */
export const defaultAppDataUpdateCallback: AppDataUpdateCallback = (_componentId, _currentData, updates) =>
  updates.at(-1)

/**
 * Applies a list of AppDataUpdates (in commit order) to the `app_data_dictionary`
 * extension contained in the given GroupContext extension list, per
 * draft-ietf-mls-extensions-09 Section 4.7. Returns the new extension list.
 */
export function applyAppDataUpdates(
  extensions: GroupContextExtension[],
  updates: AppDataUpdate[],
  callback: AppDataUpdateCallback,
): GroupContextExtension[] {
  const dictionary = [...(getAppDataDictionary(extensions) ?? [])]

  const updatesByComponent = new Map<number, AppDataUpdate[]>()
  for (const update of updates) {
    const componentUpdates = updatesByComponent.get(update.componentId) ?? []
    componentUpdates.push(update)
    updatesByComponent.set(update.componentId, componentUpdates)
  }

  for (const [componentId, componentUpdates] of updatesByComponent) {
    const entryIndex = dictionary.findIndex((e) => e.componentId === componentId)
    const containsRemove = componentUpdates.some((u) => u.operation === "remove")

    if (containsRemove) {
      if (componentUpdates.length > 1)
        throw new ValidationError(
          "Commit cannot contain multiple AppDataUpdate proposals that remove state for the same component or both update and remove state for the same component",
        )

      if (entryIndex === -1)
        throw new ValidationError("AppDataUpdate cannot remove state for a component that has no state present")

      dictionary.splice(entryIndex, 1)
    } else {
      const newData = callback(
        componentId,
        entryIndex === -1 ? undefined : dictionary[entryIndex]!.data,
        componentUpdates.flatMap((u) => (u.operation === "update" ? [u.update] : [])),
      )

      if (newData === undefined)
        throw new ValidationError("Application logic considered the AppDataUpdate proposals for a component invalid")

      if (entryIndex === -1) {
        const insertAt = dictionary.findIndex((e) => e.componentId > componentId)
        dictionary.splice(insertAt === -1 ? dictionary.length : insertAt, 0, { componentId, data: newData })
      } else {
        dictionary[entryIndex] = { componentId, data: newData }
      }
    }
  }

  const newExtension = makeAppDataDictionaryExtension(dictionary)
  const extensionIndex = extensions.findIndex((e) => e.extensionType === appDataDictionaryExtensionType)

  return extensionIndex === -1
    ? [...extensions, newExtension]
    : extensions.map((e, i) => (i === extensionIndex ? newExtension : e))
}
