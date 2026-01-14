import { uint64Decoder, uint64Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder, encode } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenTypeDecoder, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CiphersuiteId, ciphersuiteEncoder, ciphersuiteDecoder } from "./crypto/ciphersuite.js"

import { expandWithLabel, Kdf } from "./crypto/kdf.js"
import { extensionDecoder, extensionEncoder, Extension } from "./extension.js"

import { protocolVersionDecoder, protocolVersionEncoder, ProtocolVersionValue } from "./protocolVersion.js"

/** @public */
export interface GroupContext {
  version: ProtocolVersionValue
  cipherSuite: CiphersuiteId
  groupId: Uint8Array
  epoch: bigint
  treeHash: Uint8Array
  confirmedTranscriptHash: Uint8Array
  extensions: Extension[]
}

export const groupContextEncoder: Encoder<GroupContext> = contramapBufferEncoders(
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

export const groupContextDecoder: Decoder<GroupContext> = mapDecoders(
  [
    protocolVersionDecoder,
    ciphersuiteDecoder,
    varLenDataDecoder, // groupId
    uint64Decoder, // epoch
    varLenDataDecoder, // treeHash
    varLenDataDecoder, // confirmedTranscriptHash
    varLenTypeDecoder(extensionDecoder),
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
