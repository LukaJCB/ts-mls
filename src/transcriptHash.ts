import { Decoder, mapDecodersOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { Hash } from "./crypto/hash.js"
import { decodeFramedContent, FramedContentCommit, framedContentEncoder } from "./framedContent.js"
import { decodeWireformat, wireformatEncoder, WireformatValue } from "./wireformat.js"
import { contentTypes } from "./contentType.js"

export interface ConfirmedTranscriptHashInput {
  wireformat: WireformatValue
  content: FramedContentCommit
  signature: Uint8Array
}

export const confirmedTranscriptHashInputEncoder: BufferEncoder<ConfirmedTranscriptHashInput> = contramapBufferEncoders(
  [wireformatEncoder, framedContentEncoder, varLenDataEncoder],
  (input) => [input.wireformat, input.content, input.signature] as const,
)

export const decodeConfirmedTranscriptHashInput: Decoder<ConfirmedTranscriptHashInput> = mapDecodersOption(
  [decodeWireformat, decodeFramedContent, decodeVarLenData],
  (wireformat, content, signature) => {
    if (content.contentType === contentTypes.commit)
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
  const [len, write] = confirmedTranscriptHashInputEncoder(input)
  const buf = new ArrayBuffer(interimTranscriptHash.byteLength + len)
  const arr = new Uint8Array(buf)
  arr.set(interimTranscriptHash, 0)
  write(interimTranscriptHash.byteLength, buf)

  return hash.digest(arr)
}

export function createInterimHash(
  confirmedHash: Uint8Array,
  confirmationTag: Uint8Array,
  hash: Hash,
): Promise<Uint8Array> {
  const [len, write] = varLenDataEncoder(confirmationTag)
  const buf = new ArrayBuffer(confirmedHash.byteLength + len)
  const arr = new Uint8Array(buf)
  arr.set(confirmedHash, 0)
  write(confirmedHash.byteLength, buf)
  return hash.digest(arr)
}
