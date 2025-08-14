import { decodeUint64, encodeUint64 } from "./codec/number"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite"

import { expandWithLabel, Kdf } from "./crypto/kdf"
import { decodeExtension, encodeExtension, Extension } from "./extension"

import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion"

export interface GroupContext {
  version: ProtocolVersionName
  cipherSuite: CiphersuiteName
  groupId: Uint8Array
  epoch: bigint
  treeHash: Uint8Array
  confirmedTranscriptHash: Uint8Array
  extensions: Extension[]
}

export const encodeGroupContext: Encoder<GroupContext> = contramapEncoders(
  [
    encodeProtocolVersion,
    encodeCiphersuite,
    encodeVarLenData, // groupId
    encodeUint64, // epoch
    encodeVarLenData, // treeHash
    encodeVarLenData, // confirmedTranscriptHash
    encodeVarLenType(encodeExtension),
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

  return expandWithLabel(extracted, "epoch", encodeGroupContext(context), kdf.size, kdf)
}

export async function extractJoinerSecret(
  context: GroupContext,
  previousInitSecret: Uint8Array,
  commitSecret: Uint8Array,
  kdf: Kdf,
) {
  const extracted = await kdf.extract(previousInitSecret, commitSecret)

  return expandWithLabel(extracted, "joiner", encodeGroupContext(context), kdf.size, kdf)
}
