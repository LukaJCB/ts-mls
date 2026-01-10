import { decodeUint32, uint32Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import {
  decodeNumberRecord,
  decodeVarLenData,
  decodeVarLenType,
  numberRecordEncoder,
  varLenDataEncoder,
  varLenTypeEncoder,
} from "./codec/variableLength.js"
import { ContentTypeName } from "./contentType.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Kdf, expandWithLabel, deriveTreeSecret } from "./crypto/kdf.js"
import { KeyRetentionConfig } from "./keyRetentionConfig.js"
import { InternalError, ValidationError } from "./mlsError.js"
import { ReuseGuard, SenderData } from "./sender.js"
import { nodeWidth, root, right, isLeaf, left, leafToNodeIndex, NodeIndex, toLeafIndex } from "./treemath.js"

export interface GenerationSecret {
  secret: Uint8Array
  generation: number
  unusedGenerations: Record<number, Uint8Array>
}

export const generationSecretEncoder: BufferEncoder<GenerationSecret> = contramapBufferEncoders(
  [varLenDataEncoder, uint32Encoder, numberRecordEncoder(uint32Encoder, varLenDataEncoder)],
  (gs) => [gs.secret, gs.generation, gs.unusedGenerations] as const,
)

export const decodeGenerationSecret: Decoder<GenerationSecret> = mapDecoders(
  [decodeVarLenData, decodeUint32, decodeNumberRecord(decodeUint32, decodeVarLenData)],
  (secret, generation, unusedGenerations) => ({
    secret,
    generation,
    unusedGenerations,
  }),
)

export interface SecretTreeNode {
  handshake: GenerationSecret
  application: GenerationSecret
}

export const secretTreeNodeEncoder: BufferEncoder<SecretTreeNode> = contramapBufferEncoders(
  [generationSecretEncoder, generationSecretEncoder],
  (node) => [node.handshake, node.application] as const,
)

export const decodeSecretTreeNode: Decoder<SecretTreeNode> = mapDecoders(
  [decodeGenerationSecret, decodeGenerationSecret],
  (handshake, application) => ({
    handshake,
    application,
  }),
)

export type SecretTree = SecretTreeNode[]

export const secretTreeEncoder: BufferEncoder<SecretTree> = varLenTypeEncoder(secretTreeNodeEncoder)

export const decodeSecretTree: Decoder<SecretTree> = decodeVarLenType(decodeSecretTreeNode)

export function allSecretTreeValues(tree: SecretTree): Uint8Array[] {
  const arr = new Array<Uint8Array>(tree.length * 2)
  for (const node of tree) {
    arr.push(node.application.secret)
    arr.push(node.handshake.secret)
    for (const gen of Object.values(node.application.unusedGenerations)) {
      arr.push(gen)
    }
    for (const gen of Object.values(node.handshake.unusedGenerations)) {
      arr.push(gen)
    }
  }
  return arr
}

export interface ConsumeRatchetResult {
  nonce: Uint8Array
  reuseGuard: ReuseGuard
  key: Uint8Array
  generation: number
  newTree: SecretTree
  consumed: Uint8Array[]
}

function scaffoldSecretTree(leafWidth: number, encryptionSecret: Uint8Array, kdf: Kdf): Promise<Uint8Array[]> {
  const tree = new Array<Uint8Array>(nodeWidth(leafWidth))
  const rootIndex = root(leafWidth)

  tree[rootIndex] = encryptionSecret
  return deriveChildren(tree, rootIndex, kdf)
}

export async function createSecretTree(leafWidth: number, encryptionSecret: Uint8Array, kdf: Kdf): Promise<SecretTree> {
  const tree = await scaffoldSecretTree(leafWidth, encryptionSecret, kdf)

  return await Promise.all(
    tree.map(async (secret) => {
      const application = await createRatchetRoot(secret, "application", kdf)
      const handshake = await createRatchetRoot(secret, "handshake", kdf)

      return { handshake, application }
    }),
  )
}

async function deriveChildren(tree: Uint8Array[], nodeIndex: NodeIndex, kdf: Kdf): Promise<Uint8Array[]> {
  if (isLeaf(nodeIndex)) return tree
  const l = left(nodeIndex)

  const r = right(nodeIndex)

  const parentSecret = tree[nodeIndex]
  if (parentSecret === undefined) throw new InternalError("Bad node index for secret tree")
  const leftSecret = await expandWithLabel(parentSecret, "tree", new TextEncoder().encode("left"), kdf.size, kdf)

  const rightSecret = await expandWithLabel(parentSecret, "tree", new TextEncoder().encode("right"), kdf.size, kdf)

  tree[l] = leftSecret
  tree[r] = rightSecret

  return deriveChildren(await deriveChildren(tree, l, kdf), r, kdf)
}

export async function deriveNonce(secret: Uint8Array, generation: number, cs: CiphersuiteImpl): Promise<Uint8Array> {
  return await deriveTreeSecret(secret, "nonce", generation, cs.hpke.nonceLength, cs.kdf)
}

export async function deriveKey(secret: Uint8Array, generation: number, cs: CiphersuiteImpl): Promise<Uint8Array> {
  return await deriveTreeSecret(secret, "key", generation, cs.hpke.keyLength, cs.kdf)
}

export async function ratchetUntil(
  current: GenerationSecret,
  desiredGen: number,
  config: KeyRetentionConfig,
  kdf: Kdf,
): Promise<[GenerationSecret, Uint8Array[]]> {
  const generationDifference = desiredGen - current.generation

  if (generationDifference > config.maximumForwardRatchetSteps)
    throw new ValidationError("Desired generation too far in the future")

  const consumed: Uint8Array[] = []
  let result: GenerationSecret = { ...current }

  for (let i = 0; i < generationDifference; i++) {
    const nextSecret = await deriveTreeSecret(result.secret, "secret", result.generation, kdf.size, kdf)

    const [updated, old] = updateUnusedGenerations(result, config.retainKeysForGenerations)
    consumed.push(...old)

    result = {
      secret: nextSecret,
      generation: result.generation + 1,
      unusedGenerations: updated,
    }
  }

  return [result, consumed]
}

function updateUnusedGenerations(
  s: GenerationSecret,
  retainGenerationsMax: number,
): [Record<number, Uint8Array>, Uint8Array[]] {
  const withNew: Record<number, Uint8Array> = { ...s.unusedGenerations, [s.generation]: s.secret }

  const generations = Object.keys(withNew)

  const result: [Record<number, Uint8Array>, Uint8Array[]] =
    generations.length >= retainGenerationsMax ? removeOldGenerations(withNew, retainGenerationsMax) : [withNew, []]

  return result
}

function removeOldGenerations(
  unusedGenerations: Record<number, Uint8Array>,
  max: number,
): [Record<number, Uint8Array>, Uint8Array[]] {
  const generations = Object.keys(unusedGenerations)
    .map(Number)
    .sort((a, b) => a - b)

  const cutoff = generations.length - max

  const consumed = new Array<Uint8Array>()
  const record: Record<number, Uint8Array> = {}

  for (const [n, gen] of generations.entries()) {
    const value = unusedGenerations[gen]!
    if (n < cutoff) {
      consumed.push(value)
    } else {
      record[gen] = value
    }
  }

  return [record, consumed]
}

export async function derivePrivateMessageNonce(
  secret: Uint8Array,
  generation: number,
  reuseGuard: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<Uint8Array> {
  const nonce = await deriveNonce(secret, generation, cs)

  if (nonce.length >= 4 && reuseGuard.length >= 4) {
    for (let i = 0; i < 4; i++) {
      nonce[i]! ^= reuseGuard[i]!
    }
  } else throw new ValidationError("Reuse guard or nonce incorrect length")

  return nonce
}

export async function ratchetToGeneration(
  tree: SecretTree,
  senderData: SenderData,
  contentType: ContentTypeName,
  config: KeyRetentionConfig,
  cs: CiphersuiteImpl,
): Promise<ConsumeRatchetResult> {
  const index = leafToNodeIndex(toLeafIndex(senderData.leafIndex))
  const node = tree[index]
  if (node === undefined) throw new InternalError("Bad node index for secret tree")

  const ratchet = ratchetForContentType(node, contentType)

  if (ratchet.generation > senderData.generation) {
    const desired = ratchet.unusedGenerations[senderData.generation]

    if (desired !== undefined) {
      const { [senderData.generation]: _, ...removedDesiredGen } = ratchet.unusedGenerations
      const ratchetState = { ...ratchet, unusedGenerations: removedDesiredGen }

      return await createRatchetResultWithSecret(
        node,
        index,
        desired,
        senderData.generation,
        senderData.reuseGuard,
        tree,
        contentType,
        [],
        cs,
        ratchetState,
      )
    }
    throw new ValidationError("Desired gen in the past")
  }

  const [currentSecret, consumed] = await ratchetUntil(
    ratchetForContentType(node, contentType),
    senderData.generation,
    config,
    cs.kdf,
  )

  return createRatchetResult(node, index, currentSecret, senderData.reuseGuard, tree, contentType, consumed, cs)
}

export async function consumeRatchet(
  tree: SecretTree,
  index: number,
  contentType: ContentTypeName,
  cs: CiphersuiteImpl,
): Promise<ConsumeRatchetResult> {
  const node = tree[index]
  if (node === undefined) throw new InternalError("Bad node index for secret tree")

  const currentSecret = ratchetForContentType(node, contentType)
  const reuseGuard = cs.rng.randomBytes(4) as ReuseGuard

  return createRatchetResult(node, index, currentSecret, reuseGuard, tree, contentType, [], cs)
}

async function createRatchetResult(
  node: SecretTreeNode,
  index: number,
  currentSecret: GenerationSecret,
  reuseGuard: ReuseGuard,
  tree: SecretTree,
  contentType: ContentTypeName,
  consumed: Uint8Array[],
  cs: CiphersuiteImpl,
): Promise<ConsumeRatchetResult> {
  const nextSecret = await deriveTreeSecret(
    currentSecret.secret,
    "secret",
    currentSecret.generation,
    cs.kdf.size,
    cs.kdf,
  )

  const ratchetState = { ...currentSecret, secret: nextSecret, generation: currentSecret.generation + 1 }

  return await createRatchetResultWithSecret(
    node,
    index,
    currentSecret.secret,
    currentSecret.generation,
    reuseGuard,
    tree,
    contentType,
    consumed,
    cs,
    ratchetState,
  )
}

async function createRatchetResultWithSecret(
  node: SecretTreeNode,
  index: number,
  secret: Uint8Array,
  generation: number,
  reuseGuard: ReuseGuard,
  tree: SecretTree,
  contentType: ContentTypeName,
  consumed: Uint8Array[],
  cs: CiphersuiteImpl,
  ratchetState: GenerationSecret,
): Promise<ConsumeRatchetResult> {
  const { nonce, key } = await createKeyAndNonce(secret, generation, reuseGuard, cs)

  const newNode =
    contentType === "application" ? { ...node, application: ratchetState } : { ...node, handshake: ratchetState }

  const newTree = tree.slice()
  newTree[index] = newNode

  return {
    generation: generation,
    reuseGuard,
    nonce,
    key,
    newTree,
    consumed: [...consumed, secret, key],
  }
}

async function createKeyAndNonce(secret: Uint8Array, generation: number, reuseGuard: ReuseGuard, cs: CiphersuiteImpl) {
  const key = await deriveKey(secret, generation, cs)
  const nonce = await derivePrivateMessageNonce(secret, generation, reuseGuard, cs)
  return { nonce, key }
}

function ratchetForContentType(node: SecretTreeNode, contentType: ContentTypeName): GenerationSecret {
  switch (contentType) {
    case "application":
      return node.application
    case "proposal":
      return node.handshake
    case "commit":
      return node.handshake
  }
}

async function createRatchetRoot(node: Uint8Array, label: string, kdf: Kdf) {
  const secret = await expandWithLabel(node, label, new Uint8Array(), kdf.size, kdf)
  return { secret: secret, generation: 0, unusedGenerations: {} }
}
