import { uint32Encoder, uint32Decoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { varLenDataEncoder, varLenTypeEncoder, varLenDataDecoder, varLenTypeDecoder } from "./codec/variableLength.js"

/** @public */
export interface ParentNode {
  hpkePublicKey: Uint8Array
  parentHash: Uint8Array
  unmergedLeaves: number[]
}

export const parentNodeEncoder: BufferEncoder<ParentNode> = contramapBufferEncoders(
  [varLenDataEncoder, varLenDataEncoder, varLenTypeEncoder(uint32Encoder)],
  (node) => [node.hpkePublicKey, node.parentHash, node.unmergedLeaves] as const,
)

export const parentNodeDecoder: Decoder<ParentNode> = mapDecoders(
  [varLenDataDecoder, varLenDataDecoder, varLenTypeDecoder(uint32Decoder)],
  (hpkePublicKey, parentHash, unmergedLeaves) => ({
    hpkePublicKey,
    parentHash,
    unmergedLeaves,
  }),
)
