import { Decoder, mapDecodersOption } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { Hash } from "./crypto/hash"
import { decodeFramedContent, encodeFramedContent, FramedContentCommit } from "./framedContent"
import { decodeWireformat, encodeWireformat, WireformatName } from "./wireformat"

export interface ConfirmedTranscriptHashInput {
  wireformat: WireformatName
  content: FramedContentCommit
  signature: Uint8Array
}

export const encodeConfirmedTranscriptHashInput: Encoder<ConfirmedTranscriptHashInput> = contramapEncoders(
  [encodeWireformat, encodeFramedContent, encodeVarLenData],
  (input) => [input.wireformat, input.content, input.signature] as const,
)

export const decodeConfirmedTranscriptHashInput: Decoder<ConfirmedTranscriptHashInput> = mapDecodersOption(
  [decodeWireformat, decodeFramedContent, decodeVarLenData],
  (wireformat, content, signature) => {
    if (content.contentType === "commit")
      return {
        wireformat,
        content,
        signature,
      }
    else return undefined
  },
)

export function createConfirmedHash(
  interimTranscriptHash: Uint8Array,
  input: ConfirmedTranscriptHashInput,
  hash: Hash,
): Promise<Uint8Array> {
  return hash.digest(new Uint8Array([...interimTranscriptHash, ...encodeConfirmedTranscriptHashInput(input)]))
}

export function createInterimHash(
  confirmedHash: Uint8Array,
  confirmationTag: Uint8Array,
  hash: Hash,
): Promise<Uint8Array> {
  return hash.digest(new Uint8Array([...confirmedHash, ...encodeVarLenData(confirmationTag)]))
}
