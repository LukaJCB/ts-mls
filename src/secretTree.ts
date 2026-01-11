import { decodeUint32, uint32Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { decodeNumberRecord, decodeVarLenData, numberRecordEncoder, varLenDataEncoder } from "./codec/variableLength.js"
import { ContentTypeName } from "./contentType.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Kdf, expandWithLabel, deriveTreeSecret } from "./crypto/kdf.js"
import { KeyRetentionConfig } from "./keyRetentionConfig.js"
import { InternalError, ValidationError } from "./mlsError.js"
import { ReuseGuard, SenderData } from "./sender.js"
import { root, right, left, toLeafIndex, LeafIndex, leafToNodeIndex, NodeIndex, parent } from "./treemath.js"

/** @public */
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

/** @public */
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

/** @public */
export interface SecretTree {
  leafWidth: number
  intermediateNodes: Record<number, Uint8Array>
  leafNodes: Record<number, SecretTreeNode>
}

export const secretTreeEncoder: BufferEncoder<SecretTree> = contramapBufferEncoders(
  [
    uint32Encoder,
    numberRecordEncoder(uint32Encoder, varLenDataEncoder),
    numberRecordEncoder(uint32Encoder, secretTreeNodeEncoder),
  ],
  (st) => [st.leafWidth, st.intermediateNodes, st.leafNodes] as const,
)

export const decodeSecretTree: Decoder<SecretTree> = mapDecoders(
  [
    decodeUint32,
    decodeNumberRecord(decodeUint32, decodeVarLenData),
    decodeNumberRecord(decodeUint32, decodeSecretTreeNode),
  ],
  (leafWidth, intermediateNodes, leafNodes) => ({ leafWidth, intermediateNodes, leafNodes }),
)

export function allSecretTreeValues(tree: SecretTree): Uint8Array[] {
  const arr = new Array<Uint8Array>(tree.leafWidth * 2)
  for (const node of Object.values(tree.leafNodes)) {
    arr.push(node.application.secret)
    arr.push(node.handshake.secret)
    for (const gen of Object.values(node.application.unusedGenerations)) {
      arr.push(gen)
    }
    for (const gen of Object.values(node.handshake.unusedGenerations)) {
      arr.push(gen)
    }
  }

  for (const node of Object.values(tree.intermediateNodes)) {
    arr.push(node)
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

    const leftSecret = await expandWithLabel(currentSecret, "tree", new TextEncoder().encode("left"), kdf.size, kdf)
    const rightSecret = await expandWithLabel(currentSecret, "tree", new TextEncoder().encode("right"), kdf.size, kdf)

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
  const index = toLeafIndex(senderData.leafIndex)
  const nodeIndex = leafToNodeIndex(index)

  const [updatedTree, consumedSecrets] = await updateTreeWithLeafSecret(tree, index, nodeIndex, cs)

  const node = updatedTree.leafNodes[nodeIndex]!

  const ratchet = ratchetForContentType(node, contentType)

  if (ratchet.generation > senderData.generation) {
    const desired = ratchet.unusedGenerations[senderData.generation]

    if (desired !== undefined) {
      const { [senderData.generation]: consumedValue, ...removedDesiredGen } = ratchet.unusedGenerations
      const ratchetState = { ...ratchet, unusedGenerations: removedDesiredGen }

      const consumed = consumedValue ? [...consumedSecrets, consumedValue] : consumedSecrets

      return await createRatchetResultWithSecret(
        node,
        nodeIndex,
        desired,
        senderData.generation,
        senderData.reuseGuard,
        updatedTree,
        contentType,
        consumed,
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
  contentType: ContentTypeName,
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
    leafToNodeIndex(index),
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
  index: NodeIndex,
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

export async function createRatchetRoot(node: Uint8Array, label: string, kdf: Kdf) {
  const secret = await expandWithLabel(node, label, new Uint8Array(), kdf.size, kdf)
  return { secret: secret, generation: 0, unusedGenerations: {} }
}
