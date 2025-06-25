import { ContentTypeName } from "./contentType"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Kdf, expandWithLabel, deriveTreeSecret } from "./crypto/kdf"
import { ReuseGuard, SenderData } from "./sender"
import { nodeWidth, root, right, isLeaf, left, leafToNodeIndex } from "./treemath"
import { updateArray } from "./util/array"
import { repeatAsync } from "./util/repeat"

export type GenerationSecret = { secret: Uint8Array; generation: number; unusedGenerations: Record<number, Uint8Array> }

export type SecretTreeNode = { handshake: GenerationSecret; application: GenerationSecret }

export type SecretTree = SecretTreeNode[]

export type ConsumeRatchetResult = {
  nonce: Uint8Array
  reuseGuard: ReuseGuard
  key: Uint8Array
  generation: number
  newTree: SecretTree
}

function scaffoldSecretTree(leafWidth: number, encryptionSecret: Uint8Array, kdf: Kdf): Promise<Uint8Array[]> {
  const tree = new Array(nodeWidth(leafWidth))
  const rootIndex = root(leafWidth)

  const parentInhabited = updateArray(tree, rootIndex, encryptionSecret)
  return deriveChildren(parentInhabited, rootIndex, kdf)
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

async function deriveChildren(tree: Uint8Array[], nodeIndex: number, kdf: Kdf): Promise<Uint8Array[]> {
  if (isLeaf(nodeIndex)) return tree
  const l = left(nodeIndex)

  const r = right(nodeIndex)

  const parentSecret = tree[nodeIndex]
  if (parentSecret === undefined) throw new Error("Bad node index for secret tree")
  const leftSecret = await expandWithLabel(parentSecret, "tree", new TextEncoder().encode("left"), kdf.size, kdf)

  const rightSecret = await expandWithLabel(parentSecret, "tree", new TextEncoder().encode("right"), kdf.size, kdf)

  const currentTree = updateArray(updateArray(tree, l, leftSecret), r, rightSecret)

  return deriveChildren(await deriveChildren(currentTree, l, kdf), r, kdf)
}

export async function deriveNonce(secret: Uint8Array, generation: number, cs: CiphersuiteImpl): Promise<Uint8Array> {
  return await deriveTreeSecret(secret, "nonce", generation, cs.hpke.nonceLength, cs.kdf)
}

export async function deriveKey(secret: Uint8Array, generation: number, cs: CiphersuiteImpl): Promise<Uint8Array> {
  return await deriveTreeSecret(secret, "key", generation, cs.hpke.keyLength, cs.kdf)
}

export async function ratchetUntil(current: GenerationSecret, desiredGen: number, kdf: Kdf): Promise<GenerationSecret> {
  if (current.generation > desiredGen) {
    const desired = current.unusedGenerations[desiredGen]

    if (desired !== undefined) {
      const { [desiredGen]: _, ...removeDesiredGen } = current.unusedGenerations
      return {
        ...current,
        unusedGenerations: removeDesiredGen,
      }
    }
    throw new Error("Desired gen in the past")
  }
  const generationDifference = desiredGen - current.generation

  return await repeatAsync(
    async (s) => {
      const nextSecret = await deriveTreeSecret(s.secret, "secret", s.generation, kdf.size, kdf)
      return {
        secret: nextSecret,
        generation: s.generation + 1,
        unusedGenerations: { ...s.unusedGenerations, [s.generation]: s.secret },
      }
    },
    current,
    generationDifference,
  )
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
  } else throw new Error("Reuse guard or nonce incorrect length")

  return nonce
}

export async function ratchetToGeneration(
  tree: SecretTree,
  senderData: SenderData,
  contentType: ContentTypeName,
  cs: CiphersuiteImpl,
): Promise<ConsumeRatchetResult> {
  const index = leafToNodeIndex(senderData.leafIndex)
  const node = tree[index]
  if (node === undefined) throw new Error("Bad node index for secret tree")

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
        cs,
        ratchetState,
      )
    }
    throw new Error("Desired gen in the past")
  }

  const currentSecret = await ratchetUntil(ratchetForContentType(node, contentType), senderData.generation, cs.kdf)

  return createRatchetResult(node, index, currentSecret, senderData.reuseGuard, tree, contentType, cs)
}

export async function consumeRatchet(
  tree: SecretTree,
  index: number,
  contentType: ContentTypeName,
  cs: CiphersuiteImpl,
): Promise<ConsumeRatchetResult> {
  const node = tree[index]
  if (node === undefined) throw new Error("Bad node index for secret tree")

  const currentSecret = ratchetForContentType(node, contentType)
  const reuseGuard = cs.rng.randomBytes(4) as ReuseGuard

  return createRatchetResult(node, index, currentSecret, reuseGuard, tree, contentType, cs)
}

async function createRatchetResult(
  node: SecretTreeNode,
  index: number,
  currentSecret: GenerationSecret,
  reuseGuard: ReuseGuard,
  tree: SecretTree,
  contentType: ContentTypeName,
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
  cs: CiphersuiteImpl,
  ratchetState: GenerationSecret,
): Promise<ConsumeRatchetResult> {
  const { nonce, key } = await createKeyAndNonce(secret, generation, reuseGuard, cs)

  const newNode =
    contentType === "application" ? { ...node, application: ratchetState } : { ...node, handshake: ratchetState }

  const newTree = updateArray(tree, index, newNode)

  return {
    generation: generation,
    reuseGuard,
    nonce,
    key,
    newTree,
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
