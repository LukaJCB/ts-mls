import { ClientState } from "./clientState.js"
import { uint32Decoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { encode, Encoder } from "./codec/tlsEncoder.js"
import { bigintMapDecoder, numberRecordDecoder, varLenDataDecoder, varLenTypeDecoder } from "./codec/variableLength.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { deriveTreeSecret } from "./crypto/kdf.js"
import { EpochReceiverData } from "./epochReceiverData.js"
import { groupActiveStateDecoder, groupActiveStateEncoder } from "./groupActiveState.js"
import { groupContextDecoder, groupContextEncoder } from "./groupContext.js"
import { KeySchedule } from "./keySchedule.js"
import { CodecError, UsageError } from "./mlsError.js"
import { privateKeyPathDecoder } from "./privateKeyPath.js"
import { ratchetTreeDecoder, ratchetTreeEncoder } from "./ratchetTree.js"
import { GenerationSecret, KeyAndNonce, SecretTree, SecretTreeNode } from "./secretTree.js"
import { leafWidth } from "./treemath.js"
import { unappliedProposalsDecoder, unappliedProposalsEncoder } from "./unappliedProposals.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"

// These fields retain their wire format. Refuse interpretations that would
// change signed/hashed bytes, such as the old non-RFC external_senders format
function compatibleDecoder<T>(decoder: Decoder<T>, encoder: Encoder<T>): Decoder<T> {
  return (bytes, offset) => {
    const decoded = decoder(bytes, offset)
    if (decoded === undefined) return undefined
    if (!constantTimeEqual(encode(encoder, decoded[0]), bytes.subarray(offset, offset + decoded[1]))) {
      throw new CodecError("Unsupported 1.x encoding: authenticated data would change")
    }
    return decoded
  }
}

const groupContextV1Decoder = compatibleDecoder(groupContextDecoder, groupContextEncoder)
const ratchetTreeV1Decoder = compatibleDecoder(ratchetTreeDecoder, ratchetTreeEncoder)

interface GenerationSecretV1 {
  secret: Uint8Array
  generation: number
  unusedGenerations: Record<number, Uint8Array>
}

interface SecretTreeNodeV1 {
  handshake: GenerationSecretV1
  application: GenerationSecretV1
}

type EpochReceiverDataV1 = Omit<EpochReceiverData, "secretTree"> & { secretTree: SecretTreeNodeV1[] }

const generationSecretV1Decoder: Decoder<GenerationSecretV1> = mapDecoders(
  [varLenDataDecoder, uint32Decoder, numberRecordDecoder(uint32Decoder, varLenDataDecoder)],
  (secret, generation, unusedGenerations) => ({ secret, generation, unusedGenerations }),
)

const secretTreeV1Decoder = varLenTypeDecoder(
  mapDecoders([generationSecretV1Decoder, generationSecretV1Decoder], (handshake, application) => ({
    handshake,
    application,
  })),
)

// 1.x retained two obsolete slots even after it stopped storing these secrets
const keyScheduleV1Decoder: Decoder<KeySchedule> = mapDecoders(
  [
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
  ],
  (
    _epochSecret,
    senderDataSecret,
    _encryptionSecret,
    exporterSecret,
    externalSecret,
    confirmationKey,
    membershipKey,
    resumptionPsk,
    epochAuthenticator,
    initSecret,
  ) => ({
    senderDataSecret,
    exporterSecret,
    externalSecret,
    confirmationKey,
    membershipKey,
    resumptionPsk,
    epochAuthenticator,
    initSecret,
  }),
)

const epochReceiverDataV1Decoder: Decoder<EpochReceiverDataV1> = mapDecoders(
  [varLenDataDecoder, secretTreeV1Decoder, ratchetTreeV1Decoder, varLenDataDecoder, groupContextV1Decoder],
  (resumptionPsk, secretTree, ratchetTree, senderDataSecret, groupContext) => ({
    resumptionPsk,
    secretTree,
    ratchetTree,
    senderDataSecret,
    groupContext,
  }),
)

const clientStateV1Decoder = mapDecoders(
  [
    groupContextV1Decoder,
    keyScheduleV1Decoder,
    secretTreeV1Decoder,
    ratchetTreeV1Decoder,
    privateKeyPathDecoder,
    varLenDataDecoder,
    compatibleDecoder(unappliedProposalsDecoder, unappliedProposalsEncoder),
    varLenDataDecoder,
    bigintMapDecoder(epochReceiverDataV1Decoder),
    compatibleDecoder(groupActiveStateDecoder, groupActiveStateEncoder),
  ],
  (
    groupContext,
    keySchedule,
    secretTree,
    ratchetTree,
    privatePath,
    signaturePrivateKey,
    unappliedProposals,
    confirmationTag,
    historicalReceiverData,
    groupActiveState,
  ) => ({
    groupContext,
    keySchedule,
    secretTree,
    ratchetTree,
    privatePath,
    signaturePrivateKey,
    unappliedProposals,
    confirmationTag,
    historicalReceiverData,
    groupActiveState,
  }),
)

async function migrateGenerationSecret(old: GenerationSecretV1, cs: CiphersuiteImpl): Promise<GenerationSecret> {
  const unusedGenerations: Record<number, KeyAndNonce> = {}
  for (const [generation, secret] of Object.entries(old.unusedGenerations)) {
    const gen = Number(generation)
    const key = await deriveTreeSecret(secret, "key", gen, cs.hpke.keyLength, cs.kdf)
    const nonce = await deriveTreeSecret(secret, "nonce", gen, cs.hpke.nonceLength, cs.kdf)
    unusedGenerations[gen] = { key, nonce }
  }
  return { secret: old.secret, generation: old.generation, unusedGenerations }
}

async function migrateSecretTree(old: SecretTreeNodeV1[], cs: CiphersuiteImpl): Promise<SecretTree> {
  if (old.length === 0 || (old.length & (old.length + 1)) !== 0) {
    throw new CodecError("Invalid 1.x secret tree size")
  }

  const leafNodes: Record<number, SecretTreeNode> = {}
  // 1.x eagerly derived ratchets for every node. Only even (leaf) indices are used.
  for (let i = 0; i < old.length; i += 2) {
    const node = old[i]!
    leafNodes[i] = {
      handshake: await migrateGenerationSecret(node.handshake, cs),
      application: await migrateGenerationSecret(node.application, cs),
    }
  }
  return { leafWidth: leafWidth(old.length), intermediateNodes: {}, leafNodes }
}

/** @public */
export interface DecodeClientStateV1Params {
  /** Bytes produced by ts-mls 1.x's encodeGroupState (including the ratchet tree). */
  encodedState: Uint8Array
  /** Must use the same ciphersuite ID and algorithms as the saved group. */
  cipherSuite: CiphersuiteImpl
  /** Defaults to 64,000,000 bytes. */
  maxInputSize?: number
}

/**
 * Decode a ts-mls 1.x binary GroupState into a 2.x ClientState, preserving
 * current and historical ratchet generations and retained message keys.
 *
 * This is asynchronous because retained generation secrets must be converted
 * to keys and nonces. Throws CodecError for malformed or trailing data, or
 * UsageError if the supplied ciphersuite does not match the saved group.
 * Supports the binary format introduced in 1.5. Legacy non-RFC encodings
 * that would change authenticated data (such as external_senders) are rejected.
 * As with clientStateDecoder, decoded secret buffers may reference the input.
 *
 * @public
 */
export async function decodeClientStateV1(params: DecodeClientStateV1Params): Promise<ClientState> {
  const { encodedState, cipherSuite, maxInputSize = 64000000 } = params
  if (encodedState.length > maxInputSize) throw new CodecError("1.x state exceeds maxInputSize")

  const decoded = clientStateV1Decoder(encodedState, 0)
  if (decoded === undefined || decoded[1] !== encodedState.length) {
    throw new CodecError("Invalid 1.x state encoding")
  }

  const [old] = decoded
  if (
    old.groupContext.cipherSuite !== cipherSuite.id ||
    [...old.historicalReceiverData.values()].some((data) => data.groupContext.cipherSuite !== cipherSuite.id)
  ) {
    throw new UsageError("Ciphersuite does not match the saved 1.x state")
  }

  const secretTree = await migrateSecretTree(old.secretTree, cipherSuite)
  const historicalReceiverData = new Map<bigint, EpochReceiverData>()
  for (const [epoch, data] of old.historicalReceiverData) {
    historicalReceiverData.set(epoch, { ...data, secretTree: await migrateSecretTree(data.secretTree, cipherSuite) })
  }

  return { ...old, secretTree, historicalReceiverData, treeHashCache: [] }
}
