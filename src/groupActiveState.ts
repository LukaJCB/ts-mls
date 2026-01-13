import { stringEncoder, stringDecoder } from "./codec/string.js"
import { Decoder, flatMapDecoder, succeedDecoder, mapDecoder, failDecoder } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { Reinit, reinitEncoder, reinitDecoder } from "./proposal.js"

/** @public */
export type GroupActiveState =
  | { kind: "active" }
  | { kind: "suspendedPendingReinit"; reinit: Reinit }
  | { kind: "removedFromGroup" }
const activeEncoder: BufferEncoder<GroupActiveState> = contramapBufferEncoder(stringEncoder, () => "active")
const suspendedPendingReinitEncoder: BufferEncoder<{ kind: "suspendedPendingReinit"; reinit: Reinit }> =
  contramapBufferEncoders([stringEncoder, reinitEncoder], (s) => ["suspendedPendingReinit", s.reinit] as const)
const removedFromGroupEncoder: BufferEncoder<GroupActiveState> = contramapBufferEncoder(
  stringEncoder,
  () => "removedFromGroup",
)

export const groupActiveStateEncoder: BufferEncoder<GroupActiveState> = (state) => {
  switch (state.kind) {
    case "active":
      return activeEncoder(state)
    case "suspendedPendingReinit":
      return suspendedPendingReinitEncoder(state)
    case "removedFromGroup":
      return removedFromGroupEncoder(state)
  }
}

export const groupActiveStateDecoder: Decoder<GroupActiveState> = flatMapDecoder(
  stringDecoder,
  (kind): Decoder<GroupActiveState> => {
    switch (kind) {
      case "active":
        return succeedDecoder({ kind: "active" })

      case "suspendedPendingReinit":
        return mapDecoder(reinitDecoder, (reinit) => ({ kind: "suspendedPendingReinit", reinit }))

      case "removedFromGroup":
        return succeedDecoder({ kind: "removedFromGroup" })
      default:
        return failDecoder()
    }
  },
)
