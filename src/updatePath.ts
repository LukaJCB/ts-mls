import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Hash } from "./crypto/hash"
import { encryptWithLabel, PrivateKey } from "./crypto/hpke"
import { deriveSecret } from "./crypto/kdf"
import { encodeGroupContext, GroupContext } from "./groupContext"
import { decodeLeafNodeCommit, encodeLeafNode, LeafNodeCommit, LeafNodeTBSCommit, signLeafNodeCommit } from "./leafNode"
import { calculateParentHash } from "./parentHash"
import {
  filteredDirectPath,
  filteredDirectPathAndCopathResolution,
  getHpkePublicKey,
  Node,
  RatchetTree,
} from "./ratchetTree"
import { treeHashRoot } from "./treeHash"
import { directPath, leafToNodeIndex, leafWidth } from "./treemath"
import { updateArray } from "./util/array"
import { constantTimeEqual } from "./util/constantTimeCompare"
import { decodeHpkeCiphertext, encodeHpkeCiphertext, HPKECiphertext } from "./hpkeCiphertext"

export type UpdatePathNode = Readonly<{
  hpkePublicKey: Uint8Array
  encryptedPathSecret: HPKECiphertext[]
}>

export const encodeUpdatePathNode: Encoder<UpdatePathNode> = contramapEncoders(
  [encodeVarLenData, encodeVarLenType(encodeHpkeCiphertext)],
  (node) => [node.hpkePublicKey, node.encryptedPathSecret] as const,
)

export const decodeUpdatePathNode: Decoder<UpdatePathNode> = mapDecoders(
  [decodeVarLenData, decodeVarLenType(decodeHpkeCiphertext)],
  (hpkePublicKey, encryptedPathSecret) => ({ hpkePublicKey, encryptedPathSecret }),
)

export type UpdatePath = Readonly<{
  leafNode: LeafNodeCommit
  nodes: UpdatePathNode[]
}>

export const encodeUpdatePath: Encoder<UpdatePath> = contramapEncoders(
  [encodeLeafNode, encodeVarLenType(encodeUpdatePathNode)],
  (path) => [path.leafNode, path.nodes] as const,
)

export const decodeUpdatePath: Decoder<UpdatePath> = mapDecoders(
  [decodeLeafNodeCommit, decodeVarLenType(decodeUpdatePathNode)],
  (leafNode, nodes) => ({ leafNode, nodes }),
)

export type PathSecret = { nodeIndex: number; secret: Uint8Array; sendTo: number[] }

export async function createUpdatePath(
  originalTree: RatchetTree,
  senderLeafIndex: number,
  groupContext: GroupContext,
  signaturePrivateKey: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<[RatchetTree, UpdatePath, PathSecret[], PrivateKey]> {
  const originalLeafNode = originalTree[leafToNodeIndex(senderLeafIndex)]
  if (originalLeafNode === undefined || originalLeafNode.nodeType === "parent")
    throw new Error("Expected non-blank leaf node")

  const pathSecret = cs.rng.randomBytes(cs.kdf.size)

  const leafNodeSecret = await deriveSecret(pathSecret, "node", cs.kdf)
  const leafKeypair = await cs.hpke.deriveKeyPair(leafNodeSecret)

  const fdp = filteredDirectPathAndCopathResolution(senderLeafIndex, originalTree)

  const [ps, updatedTree]: [PathSecret[], RatchetTree] = await applyInitialTreeUpdate(
    fdp,
    pathSecret,
    senderLeafIndex,
    originalTree,
    cs,
  )

  const treeWithHashes = await insertParentHashes(fdp, updatedTree, cs)

  const leafParentHash = await calculateParentHash(treeWithHashes, leafToNodeIndex(senderLeafIndex), cs.hash)

  const updatedLeafNodeTbs: LeafNodeTBSCommit = {
    leafNodeSource: "commit",
    hpkePublicKey: await cs.hpke.exportPublicKey(leafKeypair.publicKey),
    extensions: originalLeafNode.leaf.extensions,
    capabilities: originalLeafNode.leaf.capabilities,
    credential: originalLeafNode.leaf.credential,
    signaturePublicKey: originalLeafNode.leaf.signaturePublicKey,
    parentHash: leafParentHash[0],
    info: { leafNodeSource: "commit", groupId: groupContext.groupId, leafIndex: senderLeafIndex },
  }

  const updatedLeafNode = await signLeafNodeCommit(updatedLeafNodeTbs, signaturePrivateKey, cs.signature)

  const finalTree = updateArray(treeWithHashes, leafToNodeIndex(senderLeafIndex), {
    nodeType: "leaf",
    leaf: updatedLeafNode,
  })

  const updatedTreeHash = await treeHashRoot(finalTree, cs.hash)

  const updatedGroupContext: GroupContext = {
    ...groupContext,
    treeHash: updatedTreeHash,
    epoch: groupContext.epoch + 1n,
  }

  // we have to remove the leaf secret since we don't send it to anyone
  const pathSecrets = ps.slice(0, ps.length - 1).reverse()

  // we have to pass the old tree here since the receiver won't have the updated public keys yet
  const updatePathNodes: UpdatePathNode[] = await Promise.all(
    pathSecrets.map(encryptSecretsForPath(originalTree, finalTree, updatedGroupContext, cs)),
  )

  const updatePath: UpdatePath = { leafNode: updatedLeafNode, nodes: updatePathNodes }

  return [finalTree, updatePath, pathSecrets, leafKeypair.privateKey] as const
}

function encryptSecretsForPath(
  originalTree: RatchetTree,
  updatedTree: RatchetTree,
  updatedGroupContext: GroupContext,
  cs: CiphersuiteImpl,
): (pathSecret: PathSecret) => Promise<UpdatePathNode> {
  return async (pathSecret) => {
    const key = getHpkePublicKey(updatedTree[pathSecret.nodeIndex]!)

    const res: UpdatePathNode = {
      hpkePublicKey: key,
      encryptedPathSecret: await Promise.all(
        pathSecret.sendTo.map(async (nodeIndex) => {
          const { ct, enc } = await encryptWithLabel(
            await cs.hpke.importPublicKey(getHpkePublicKey(originalTree[nodeIndex]!)),
            "UpdatePathNode",
            encodeGroupContext(updatedGroupContext),
            pathSecret.secret,
            cs.hpke,
          )
          return { ciphertext: ct, kemOutput: enc }
        }),
      ),
    }
    return res
  }
}

async function insertParentHashes(
  fdp: { resolution: number[]; nodeIndex: number }[],
  updatedTree: RatchetTree,
  cs: CiphersuiteImpl,
) {
  return await fdp
    .slice()
    .reverse()
    .reduce(async (treePromise, { nodeIndex }) => {
      const tree = await treePromise
      const parentHash = await calculateParentHash(tree, nodeIndex, cs.hash)
      const currentNode = tree[nodeIndex]
      if (currentNode === undefined || currentNode.nodeType === "leaf")
        throw new Error("Expected non-blank parent node")
      const updatedNode: Node = { nodeType: "parent", parent: { ...currentNode.parent, parentHash: parentHash[0] } }

      return updateArray(tree, nodeIndex, updatedNode)
    }, Promise.resolve(updatedTree))
}

/**
 * Inserts new public keys from a single secret in the update path and returns the resulting tree along with the secrets along the path
 * Note that the path secrets are returned root to leaf
 */
async function applyInitialTreeUpdate(
  fdp: { resolution: number[]; nodeIndex: number }[],
  pathSecret: Uint8Array,
  senderLeafIndex: number,
  tree: RatchetTree,
  cs: CiphersuiteImpl,
): Promise<[PathSecret[], RatchetTree]> {
  return await fdp.reduce(
    async (acc, { nodeIndex, resolution }) => {
      const [pathSecrets, tree] = await acc
      const lastPathSecret = pathSecrets[0]!
      const nextPathSecret = await deriveSecret(lastPathSecret.secret, "path", cs.kdf)
      const nextNodeSecret = await deriveSecret(nextPathSecret, "node", cs.kdf)
      const { publicKey } = await cs.hpke.deriveKeyPair(nextNodeSecret)

      const updatedTree = updateArray(tree, nodeIndex, {
        nodeType: "parent",
        parent: {
          hpkePublicKey: await cs.hpke.exportPublicKey(publicKey),
          parentHash: new Uint8Array(),
          unmergedLeaves: [],
        },
      })

      return [[{ nodeIndex, secret: nextPathSecret, sendTo: resolution }, ...pathSecrets], updatedTree]
    },
    Promise.resolve([[{ secret: pathSecret, nodeIndex: leafToNodeIndex(senderLeafIndex), sendTo: [] }], tree] as [
      PathSecret[],
      RatchetTree,
    ]),
  )
}

export async function applyUpdatePath(
  tree: RatchetTree,
  senderLeafIndex: number,
  path: UpdatePath,
  h: Hash,
): Promise<RatchetTree> {
  const copy = tree.slice()

  copy[leafToNodeIndex(senderLeafIndex)] = { nodeType: "leaf", leaf: path.leafNode }

  const reverseFilteredDirectPath = filteredDirectPath(senderLeafIndex, tree).reverse()

  // need to call .slice here so as not to mutate the original
  const reverseUpdatePath = path.nodes.slice().reverse()

  if (reverseUpdatePath.length !== reverseFilteredDirectPath.length) {
    throw new Error("Invalid length of UpdatePath")
  }

  for (const [level, nodeIndex] of reverseFilteredDirectPath.entries()) {
    const parentHash = await calculateParentHash(copy, nodeIndex, h)

    copy[nodeIndex] = {
      nodeType: "parent",
      parent: { hpkePublicKey: reverseUpdatePath[level]!.hpkePublicKey, unmergedLeaves: [], parentHash: parentHash[0] },
    }
  }

  const leafParentHash = await calculateParentHash(copy, leafToNodeIndex(senderLeafIndex), h)

  if (!constantTimeEqual(leafParentHash[0], path.leafNode.parentHash))
    throw new Error("Parent hash did not match the UpdatePath")

  return copy
}

function isAncestor(tree: RatchetTree, leafIndex: number, nodeIndex: number): boolean {
  return (
    directPath(leafToNodeIndex(leafIndex), leafWidth(tree.length)).find((index) => index === nodeIndex) !== undefined
  )
}

export function firstCommonAncestor(tree: RatchetTree, leafIndex: number, senderLeafIndex: number): number {
  const fdp = filteredDirectPathAndCopathResolution(senderLeafIndex, tree)

  for (const { nodeIndex } of fdp) {
    if (isAncestor(tree, leafIndex, nodeIndex)) {
      return nodeIndex
    }
  }

  throw new Error("Could not find common ancestor")
}

export function firstMatchAncestor(
  tree: RatchetTree,
  leafIndex: number,
  senderLeafIndex: number,
  path: UpdatePath,
): { nodeIndex: number; resolution: number[]; updateNode: UpdatePathNode | undefined } {
  const fdp = filteredDirectPathAndCopathResolution(senderLeafIndex, tree)

  for (const [n, { nodeIndex, resolution }] of fdp.entries()) {
    if (isAncestor(tree, leafIndex, nodeIndex)) {
      return { nodeIndex, resolution, updateNode: path.nodes[n] }
    }
  }

  throw new Error("Could not find common ancestor")
}
