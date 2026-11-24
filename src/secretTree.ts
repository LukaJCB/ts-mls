import { uint32Decoder, uint32Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { Encoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import {
  numberRecordDecoder,
  varLenDataDecoder,
  numberRecordEncoder,
  varLenDataEncoder,
} from "./codec/variableLength.js"
import { ContentTypeValue, contentTypes } from "./contentType.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Kdf, expandWithLabel, deriveTreeSecret } from "./crypto/kdf.js"
import { KeyRetentionConfig } from "./keyRetentionConfig.js"
import { InternalError, ValidationError } from "./mlsError.js"
import { ReuseGuard, SenderData } from "./sender.js"
import { root, right, left, toLeafIndex, LeafIndex, leafToNodeIndex, NodeIndex, parent } from "./treemath.js"

const _leftBytes = new TextEncoder().encode("left")
const _rightBytes = new TextEncoder().encode("right")

/** @public */
export interface GenerationSecret {
  secret: Uint8Array
  generation: number
  unusedGenerations: Record<number, KeyAndNonce>
}

/** @public */
export type KeyAndNonce = { key: Uint8Array; nonce: Uint8Array }

const keyAndNonceEncoder: Encoder<KeyAndNonce> = contramapBufferEncoders(
  [varLenDataEncoder, varLenDataEncoder],
  ({ key, nonce }) => [key, nonce] as const,
)
const keyAndNonceDecoder: Decoder<KeyAndNonce> = mapDecoders([varLenDataDecoder, varLenDataDecoder], (key, nonce) => ({
  key,
  nonce,
}))

const generationSecretEncoder: Encoder<GenerationSecret> = contramapBufferEncoders(
  [varLenDataEncoder, uint32Encoder, numberRecordEncoder(uint32Encoder, keyAndNonceEncoder)],
  (gs) => [gs.secret, gs.generation, gs.unusedGenerations] as const,
)

const generationSecretDecoder: Decoder<GenerationSecret> = mapDecoders(
  [varLenDataDecoder, uint32Decoder, numberRecordDecoder(uint32Decoder, keyAndNonceDecoder)],
  (secret, generation, unusedGenerations) => ({
    secret,
    generation,
    unusedGenerations,
  }),
)

/** @public */
export interface SecretTreeNode {
  handshake: GenerationSecret
  application: GenerationSecret
}

const secretTreeNodeEncoder: Encoder<SecretTreeNode> = contramapBufferEncoders(
  [generationSecretEncoder, generationSecretEncoder],
  (node) => [node.handshake, node.application] as const,
)

const secretTreeNodeDecoder: Decoder<SecretTreeNode> = mapDecoders(
  [generationSecretDecoder, generationSecretDecoder],
  (handshake, application) => ({
    handshake,
    application,
  }),
)

/** @public */
export interface SecretTree {
  leafWidth: number
  intermediateNodes: Record<number, Uint8Array>
  leafNodes: Record<number, SecretTreeNode>
}

export const secretTreeEncoder: Encoder<SecretTree> = contramapBufferEncoders(
  [
    uint32Encoder,
    numberRecordEncoder(uint32Encoder, varLenDataEncoder),
    numberRecordEncoder(uint32Encoder, secretTreeNodeEncoder),
  ],
  (st) => [st.leafWidth, st.intermediateNodes, st.leafNodes] as const,
)

export const secretTreeDecoder: Decoder<SecretTree> = mapDecoders(
  [
    uint32Decoder,
    numberRecordDecoder(uint32Decoder, varLenDataDecoder),
    numberRecordDecoder(uint32Decoder, secretTreeNodeDecoder),
  ],
  (leafWidth, intermediateNodes, leafNodes) => ({ leafWidth, intermediateNodes, leafNodes }),
)

export function appendSecretTreeValues(tree: SecretTree, out: Uint8Array[]): void {
  for (const node of Object.values(tree.leafNodes)) {
    out.push(node.application.secret)
    out.push(node.handshake.secret)
    for (const gen of Object.values(node.application.unusedGenerations)) {
      out.push(gen.key, gen.nonce)
    }
    for (const gen of Object.values(node.handshake.unusedGenerations)) {
      out.push(gen.key, gen.nonce)
    }
  }

  for (const node of Object.values(tree.intermediateNodes)) {
    out.push(node)
  }
}

interface ConsumeRatchetResult {
  nonce: Uint8Array
  reuseGuard: ReuseGuard
  key: Uint8Array
  generation: number
  newTree: SecretTree
  consumed: Uint8Array[]
}

async function deriveLeafSecret(
  leafIndex: LeafIndex,
  secretTree: SecretTree,
  kdf: Kdf,
): Promise<{ secret: Uint8Array; updatedIntermediateNodes: Record<NodeIndex, Uint8Array>; consumed: Uint8Array[] }> {
  const targetNodeIndex = leafToNodeIndex(leafIndex)
  const rootIndex = root(secretTree.leafWidth)

  const updatedIntermediateNodes = { ...secretTree.intermediateNodes }
  const consumed = new Array<Uint8Array>()

  // iterate from target leaf up to root
  const pathFromLeaf: NodeIndex[] = []
  let current = targetNodeIndex
  while (current !== rootIndex) {
    pathFromLeaf.push(current)
    current = parent(current, secretTree.leafWidth)
  }
  pathFromLeaf.push(rootIndex)

  // find the first existing node in the path
  let startIndex = pathFromLeaf.length - 1
  while (startIndex >= 0 && updatedIntermediateNodes[pathFromLeaf[startIndex]!] === undefined) {
    startIndex--
  }

  if (startIndex < 0) {
    throw new InternalError("No intermediate nodes found in path from leaf to root")
  }

  // derive down from the found node to the target
  current = pathFromLeaf[startIndex]!
  while (current !== targetNodeIndex) {
    const l = left(current)
    const r = right(current)

    const nextNodeIndex = targetNodeIndex < current ? l : r

    // we have to derive both children so we can delete the consumed secret
    const currentSecret = updatedIntermediateNodes[current]!

    const leftSecret = await expandWithLabel(currentSecret, "tree", _leftBytes, kdf.size, kdf)
    const rightSecret = await expandWithLabel(currentSecret, "tree", _rightBytes, kdf.size, kdf)

    updatedIntermediateNodes[l] = leftSecret
    updatedIntermediateNodes[r] = rightSecret

    consumed.push(currentSecret)

    delete updatedIntermediateNodes[current]

    current = nextNodeIndex
  }

  return { secret: updatedIntermediateNodes[targetNodeIndex]!, updatedIntermediateNodes, consumed }
}

export function createSecretTree(leafWidth: number, encryptionSecret: Uint8Array): SecretTree {
  const rootIndex = root(leafWidth)
  return {
    leafWidth,
    intermediateNodes: {
      [rootIndex]: encryptionSecret,
    },
    leafNodes: {},
  }
}

async function deriveNonce(secret: Uint8Array, generation: number, cs: CiphersuiteImpl): Promise<Uint8Array> {
  return await deriveTreeSecret(secret, "nonce", generation, cs.hpke.nonceLength, cs.kdf)
}

async function deriveKey(secret: Uint8Array, generation: number, cs: CiphersuiteImpl): Promise<Uint8Array> {
  return await deriveTreeSecret(secret, "key", generation, cs.hpke.keyLength, cs.kdf)
}

async function ratchetUntil(
  current: GenerationSecret,
  desiredGen: number,
  config: KeyRetentionConfig,
  cs: CiphersuiteImpl,
): Promise<[GenerationSecret, Uint8Array[]]> {
  const generationDifference = desiredGen - current.generation

  if (generationDifference > config.maximumForwardRatchetSteps)
    throw new ValidationError("Desired generation too far in the future")

  const consumed: Uint8Array[] = []
  let result: GenerationSecret = { ...current }

  for (let i = 0; i < generationDifference; i++) {
    const nextSecret = await deriveTreeSecret(result.secret, "secret", result.generation, cs.kdf.size, cs.kdf)
    const keyAndNonce = await createKeyAndNonce(result.secret, result.generation, cs)

    const [updated, old] = updateUnusedGenerations(result, keyAndNonce, config.retainKeysForGenerations)
    consumed.push(result.secret, ...old)

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
  keyAndNonce: KeyAndNonce,
  retainGenerationsMax: number,
): [Record<number, KeyAndNonce>, Uint8Array[]] {
  const withNew = { ...s.unusedGenerations, [s.generation]: keyAndNonce }

  const generations = Object.keys(withNew)

  const result: [Record<number, KeyAndNonce>, Uint8Array[]] =
    generations.length >= retainGenerationsMax ? removeOldGenerations(withNew, retainGenerationsMax) : [withNew, []]

  return result
}

function removeOldGenerations(
  unusedGenerations: Record<number, KeyAndNonce>,
  max: number,
): [Record<number, KeyAndNonce>, Uint8Array[]] {
  const generations = Object.keys(unusedGenerations)
    .map(Number)
    .sort((a, b) => a - b)

  const cutoff = generations.length - max

  const consumed = new Array<Uint8Array>()
  const record: Record<number, KeyAndNonce> = {}

  for (const [n, gen] of generations.entries()) {
    const value = unusedGenerations[gen]!
    if (n < cutoff) {
      consumed.push(value.key, value.nonce)
    } else {
      record[gen] = value
    }
  }

  return [record, consumed]
}

function applyReuseGuard(baseNonce: Uint8Array, reuseGuard: Uint8Array): Uint8Array {
  //copy here so that the existing nonce isn't modified in place
  const nonce = baseNonce.slice()

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
  contentType: ContentTypeValue,
  config: KeyRetentionConfig,
  cs: CiphersuiteImpl,
): Promise<ConsumeRatchetResult> {
  const index = toLeafIndex(senderData.leafIndex)
  const nodeIndex = leafToNodeIndex(index)

  const [updatedTree, consumedSecrets] = await updateTreeWithLeafSecret(tree, index, nodeIndex, cs)

  const node = updatedTree.leafNodes[nodeIndex]!

  const ratchet = ratchetForContentType(node, contentType)

  if (ratchet.generation > senderData.generation) {
    const desired = ratchet.unusedGenerations[senderData.generation]

    if (desired !== undefined) {
      const { [senderData.generation]: _, ...removedDesiredGen } = ratchet.unusedGenerations
      const ratchetState = { ...ratchet, unusedGenerations: removedDesiredGen }

      return createRatchetResultWithKeys(
        node,
        nodeIndex,
        desired,
        senderData.generation,
        senderData.reuseGuard,
        updatedTree,
        contentType,
        consumedSecrets,
        ratchetState,
      )
    }
    throw new ValidationError("Desired gen in the past")
  }

  const [currentSecret, consumed] = await ratchetUntil(
    ratchetForContentType(node, contentType),
    senderData.generation,
    config,
    cs,
  )

  return createRatchetResult(
    node,
    index,
    currentSecret,
    senderData.reuseGuard,
    updatedTree,
    contentType,
    [...consumed, ...consumedSecrets],
    cs,
  )
}

export async function consumeRatchet(
  tree: SecretTree,
  index: LeafIndex,
  contentType: ContentTypeValue,
  cs: CiphersuiteImpl,
): Promise<ConsumeRatchetResult> {
  const nodeIndex = leafToNodeIndex(index)
  const [updatedTree, consumedSecrets] = await updateTreeWithLeafSecret(tree, index, nodeIndex, cs)

  const node = updatedTree.leafNodes[nodeIndex]!

  const currentSecret = ratchetForContentType(node, contentType)
  const reuseGuard = cs.rng.randomBytes(4) as ReuseGuard

  return createRatchetResult(node, index, currentSecret, reuseGuard, updatedTree, contentType, consumedSecrets, cs)
}

async function updateTreeWithLeafSecret(
  tree: SecretTree,
  index: LeafIndex,
  nodeIndex: NodeIndex,
  cs: CiphersuiteImpl,
): Promise<[SecretTree, Uint8Array[]]> {
  const existingNode = tree.leafNodes[nodeIndex]

  if (existingNode === undefined) {
    const { secret: leafSecret, updatedIntermediateNodes, consumed } = await deriveLeafSecret(index, tree, cs.kdf)
    const application = await createRatchetRoot(leafSecret, "application", cs.kdf)
    const handshake = await createRatchetRoot(leafSecret, "handshake", cs.kdf)

    // Remove the target node from intermediate nodes since it's now a leaf
    const { [nodeIndex]: _, ...remainingIntermediateNodes } = updatedIntermediateNodes

    return [
      {
        ...tree,
        intermediateNodes: remainingIntermediateNodes,
        leafNodes: { ...tree.leafNodes, [nodeIndex]: { handshake, application } },
      },
      [...consumed, leafSecret],
    ]
  } else {
    return [tree, []]
  }
}

async function createRatchetResult(
  node: SecretTreeNode,
  index: LeafIndex,
  currentSecret: GenerationSecret,
  reuseGuard: ReuseGuard,
  tree: SecretTree,
  contentType: ContentTypeValue,
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

  return createRatchetResultWithKeys(
    node,
    leafToNodeIndex(index),
    await createKeyAndNonce(currentSecret.secret, currentSecret.generation, cs),
    currentSecret.generation,
    reuseGuard,
    tree,
    contentType,
    [...consumed, currentSecret.secret],
    ratchetState,
  )
}

function createRatchetResultWithKeys(
  node: SecretTreeNode,
  index: NodeIndex,
  keys: KeyAndNonce,
  generation: number,
  reuseGuard: ReuseGuard,
  tree: SecretTree,
  contentType: ContentTypeValue,
  consumed: Uint8Array[],
  ratchetState: GenerationSecret,
): ConsumeRatchetResult {
  const { key } = keys
  const nonce = applyReuseGuard(keys.nonce, reuseGuard)

  const newNode =
    contentType === contentTypes.application
      ? { ...node, application: ratchetState }
      : { ...node, handshake: ratchetState }

  const newTree: SecretTree = {
    ...tree,
    leafNodes: { ...tree.leafNodes, [index]: newNode },
  }

  return {
    generation: generation,
    reuseGuard,
    nonce,
    key,
    newTree,
    consumed: [...consumed, key, keys.nonce, nonce],
  }
}

async function createKeyAndNonce(secret: Uint8Array, generation: number, cs: CiphersuiteImpl): Promise<KeyAndNonce> {
  const key = await deriveKey(secret, generation, cs)
  const nonce = await deriveNonce(secret, generation, cs)
  return { nonce, key }
}

function ratchetForContentType(node: SecretTreeNode, contentType: ContentTypeValue): GenerationSecret {
  switch (contentType) {
    case contentTypes.application:
      return node.application
    case contentTypes.proposal:
      return node.handshake
    case contentTypes.commit:
      return node.handshake
  }
}

async function createRatchetRoot(node: Uint8Array, label: string, kdf: Kdf) {
  const secret = await expandWithLabel(node, label, new Uint8Array(), kdf.size, kdf)
  return { secret: secret, generation: 0, unusedGenerations: {} }
}
