import { decodeUint64, uint64Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CiphersuiteId, ciphersuiteEncoder, decodeCiphersuite } from "./crypto/ciphersuite.js"

import { expandWithLabel, Kdf } from "./crypto/kdf.js"
import { decodeExtension, extensionEncoder, GroupContextExtension } from "./extension.js"

import { decodeProtocolVersion, protocolVersionEncoder, ProtocolVersionValue } from "./protocolVersion.js"

/** @public */
export interface GroupContext {
  version: ProtocolVersionValue
  cipherSuite: CiphersuiteId
  groupId: Uint8Array
  epoch: bigint
  treeHash: Uint8Array
  confirmedTranscriptHash: Uint8Array
  extensions: GroupContextExtension[]
}

export const groupContextEncoder: BufferEncoder<GroupContext> = contramapBufferEncoders(
  [
    protocolVersionEncoder,
    ciphersuiteEncoder,
    varLenDataEncoder, // groupId
    uint64Encoder, // epoch
    varLenDataEncoder, // treeHash
    varLenDataEncoder, // confirmedTranscriptHash
    varLenTypeEncoder(extensionEncoder),
  ],
  (gc) =>
    [gc.version, gc.cipherSuite, gc.groupId, gc.epoch, gc.treeHash, gc.confirmedTranscriptHash, gc.extensions] as const,
)

export const decodeGroupContext: Decoder<GroupContext> = mapDecoders(
  [
    decodeProtocolVersion,
    decodeCiphersuite,
    decodeVarLenData, // groupId
    decodeUint64, // epoch
    decodeVarLenData, // treeHash
    decodeVarLenData, // confirmedTranscriptHash
    decodeVarLenType(decodeExtension),
  ],
  (version, cipherSuite, groupId, epoch, treeHash, confirmedTranscriptHash, extensions) => ({
    version,
    cipherSuite,
    groupId,
    epoch,
    treeHash,
    confirmedTranscriptHash,
    extensions,
  }),
)

export async function extractEpochSecret(
  context: GroupContext,
  joinerSecret: Uint8Array,
  kdf: Kdf,
  pskSecret?: Uint8Array,
) {
  const psk = pskSecret === undefined ? new Uint8Array(kdf.size) : pskSecret
  const extracted = await kdf.extract(joinerSecret, psk)

  return expandWithLabel(extracted, "epoch", encode(groupContextEncoder, context), kdf.size, kdf)
}

export async function extractJoinerSecret(
  context: GroupContext,
  previousInitSecret: Uint8Array,
  commitSecret: Uint8Array,
  kdf: Kdf,
) {
  const extracted = await kdf.extract(previousInitSecret, commitSecret)

  return expandWithLabel(extracted, "joiner", encode(groupContextEncoder, context), kdf.size, kdf)
}
