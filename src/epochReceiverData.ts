import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { varLenDataEncoder, decodeVarLenData } from "./codec/variableLength.js"
import { GroupContext, groupContextEncoder, decodeGroupContext } from "./groupContext.js"
import { RatchetTree, ratchetTreeEncoder, decodeRatchetTree } from "./ratchetTree.js"
import { SecretTree, secretTreeEncoder, decodeSecretTree } from "./secretTree.js"

/**
 * This type contains everything necessary to receieve application messages for an earlier epoch
 *
 * @public
 */
export interface EpochReceiverData {
  resumptionPsk: Uint8Array
  secretTree: SecretTree
  ratchetTree: RatchetTree
  senderDataSecret: Uint8Array
  groupContext: GroupContext
}

export const epochReceiverDataEncoder: BufferEncoder<EpochReceiverData> = contramapBufferEncoders(
  [varLenDataEncoder, secretTreeEncoder, ratchetTreeEncoder, varLenDataEncoder, groupContextEncoder],
  (erd) => [erd.resumptionPsk, erd.secretTree, erd.ratchetTree, erd.senderDataSecret, erd.groupContext] as const,
)

export const decodeEpochReceiverData: Decoder<EpochReceiverData> = mapDecoders(
  [decodeVarLenData, decodeSecretTree, decodeRatchetTree, decodeVarLenData, decodeGroupContext],
  (resumptionPsk, secretTree, ratchetTree, senderDataSecret, groupContext) => ({
    resumptionPsk,
    secretTree,
    ratchetTree,
    senderDataSecret,
    groupContext,
  }),
)
