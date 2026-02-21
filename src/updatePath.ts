import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder, encode } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenTypeDecoder, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Hash } from "./crypto/hash.js"
import { encryptWithLabel, PrivateKey } from "./crypto/hpke.js"
import { deriveSecret } from "./crypto/kdf.js"
import { groupContextEncoder, GroupContext } from "./groupContext.js"
import {
  leafNodeCommitDecoder,
  leafNodeEncoder,
  LeafNodeCommit,
  LeafNodeTBSCommit,
  signLeafNodeCommit,
} from "./leafNode.js"
import { leafNodeSources } from "./leafNodeSource.js"
import { calculateParentHash } from "./parentHash.js"
import {
  filteredDirectPath,
  filteredDirectPathAndCopathResolution,
  getHpkePublicKey,
  Node,
  RatchetTree,
} from "./ratchetTree.js"
import { nodeTypes } from "./nodeType.js"
import { treeHashRoot } from "./treeHash.js"
import { isAncestor, LeafIndex, leafToNodeIndex, NodeIndex, toNodeIndex } from "./treemath.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"
import { hpkeCiphertextDecoder, hpkeCiphertextEncoder, HPKECiphertext } from "./hpkeCiphertext.js"
import { InternalError, ValidationError } from "./mlsError.js"

/** @public */
export interface UpdatePathNode {
  hpkePublicKey: Uint8Array
  encryptedPathSecret: HPKECiphertext[]
}

export const updatePathNodeEncoder: Encoder<UpdatePathNode> = contramapBufferEncoders(
  [varLenDataEncoder, varLenTypeEncoder(hpkeCiphertextEncoder)],
  (node) => [node.hpkePublicKey, node.encryptedPathSecret] as const,
)

export const updatePathNodeDecoder: Decoder<UpdatePathNode> = mapDecoders(
  [varLenDataDecoder, varLenTypeDecoder(hpkeCiphertextDecoder)],
  (hpkePublicKey, encryptedPathSecret) => ({ hpkePublicKey, encryptedPathSecret }),
)

/** @public */
export interface UpdatePath {
  leafNode: LeafNodeCommit
  nodes: UpdatePathNode[]
}

export const updatePathEncoder: Encoder<UpdatePath> = contramapBufferEncoders(
  [leafNodeEncoder, varLenTypeEncoder(updatePathNodeEncoder)],
  (path) => [path.leafNode, path.nodes] as const,
)

export const updatePathDecoder: Decoder<UpdatePath> = mapDecoders(
  [leafNodeCommitDecoder, varLenTypeDecoder(updatePathNodeDecoder)],
  (leafNode, nodes) => ({ leafNode, nodes }),
)

export interface PathSecret {
  nodeIndex: number
  secret: Uint8Array
  sendTo: number[]
}

export async function createUpdatePath(
  originalTree: RatchetTree,
  mutableTree: RatchetTree,
  senderLeafIndex: LeafIndex,
  groupContext: GroupContext,
  signaturePrivateKey: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<[RatchetTree, UpdatePath, PathSecret[], PrivateKey]> {
  const originalLeafNode = mutableTree[leafToNodeIndex(senderLeafIndex)]
  if (originalLeafNode === undefined || originalLeafNode.nodeType === nodeTypes.parent)
    throw new InternalError("Expected non-blank leaf node")

  const pathSecret = cs.rng.randomBytes(cs.kdf.size)

  const leafNodeSecret = await deriveSecret(pathSecret, "node", cs.kdf)
  const leafKeypair = await cs.hpke.deriveKeyPair(leafNodeSecret)

  const fdp = filteredDirectPathAndCopathResolution(senderLeafIndex, mutableTree)

  const ps: PathSecret[] = await applyInitialTreeUpdate(fdp, pathSecret, senderLeafIndex, mutableTree, cs)

  await insertParentHashes(fdp, mutableTree, cs)

  const leafParentHash = await calculateParentHash(mutableTree, leafToNodeIndex(senderLeafIndex), cs.hash)

  const updatedLeafNodeTbs: LeafNodeTBSCommit = {
    leafNodeSource: leafNodeSources.commit,
    hpkePublicKey: await cs.hpke.exportPublicKey(leafKeypair.publicKey),
    extensions: originalLeafNode.leaf.extensions,
    capabilities: originalLeafNode.leaf.capabilities,
    credential: originalLeafNode.leaf.credential,
    signaturePublicKey: originalLeafNode.leaf.signaturePublicKey,
    parentHash: leafParentHash[0],
    groupId: groupContext.groupId,
    leafIndex: senderLeafIndex,
  }

  const updatedLeafNode = await signLeafNodeCommit(updatedLeafNodeTbs, signaturePrivateKey, cs.signature)

  mutableTree[leafToNodeIndex(senderLeafIndex)] = {
    nodeType: nodeTypes.leaf,
    leaf: updatedLeafNode,
  }

  const updatedTreeHash = await treeHashRoot(mutableTree, cs.hash)

  const updatedGroupContext: GroupContext = {
    ...groupContext,
    treeHash: updatedTreeHash,
    epoch: groupContext.epoch + 1n,
  }

  // we have to remove the leaf secret since we don't send it to anyone
  const pathSecrets = ps.slice(0, ps.length - 1).reverse()

  // we have to pass the old tree here since the receiver won't have the updated public keys yet
  const updatePathNodes: UpdatePathNode[] = await Promise.all(
    pathSecrets.map(encryptSecretsForPath(originalTree, mutableTree, updatedGroupContext, cs)),
  )

  const updatePath: UpdatePath = { leafNode: updatedLeafNode, nodes: updatePathNodes }

  return [mutableTree, updatePath, pathSecrets, leafKeypair.privateKey] as const
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
            encode(groupContextEncoder, updatedGroupContext),
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
  fdp: { resolution: NodeIndex[]; nodeIndex: NodeIndex }[],
  mutableTree: RatchetTree,
  cs: CiphersuiteImpl,
): Promise<void> {
  for (let x = fdp.length - 1; x >= 0; x--) {
    const { nodeIndex } = fdp[x]!
    const parentHash = await calculateParentHash(mutableTree, nodeIndex, cs.hash)
    const currentNode = mutableTree[nodeIndex]
    if (currentNode === undefined || currentNode.nodeType === nodeTypes.leaf)
      throw new InternalError("Expected non-blank parent node")
    const updatedNode: Node = {
      nodeType: nodeTypes.parent,
      parent: { ...currentNode.parent, parentHash: parentHash[0] },
    }
    mutableTree[nodeIndex] = updatedNode
  }
}

/**
 * Inserts new public keys from a single secret in the update path and returns the resulting tree along with the secrets along the path
 * Note that the path secrets are returned root to leaf
 */
async function applyInitialTreeUpdate(
  fdp: { resolution: number[]; nodeIndex: number }[],
  pathSecret: Uint8Array,
  senderLeafIndex: LeafIndex,
  mutableTree: RatchetTree,
  cs: CiphersuiteImpl,
): Promise<PathSecret[]> {
  let lastPathSecret = { secret: pathSecret, nodeIndex: leafToNodeIndex(senderLeafIndex), sendTo: new Array<number>() }
  const pathSecrets = new Array(lastPathSecret)
  for (const [_i, { nodeIndex, resolution }] of fdp.entries()) {
    const nextPathSecret = await deriveSecret(lastPathSecret.secret, "path", cs.kdf)
    const nextNodeSecret = await deriveSecret(nextPathSecret, "node", cs.kdf)
    const { publicKey } = await cs.hpke.deriveKeyPair(nextNodeSecret)

    mutableTree[nodeIndex] = {
      nodeType: nodeTypes.parent,
      parent: {
        hpkePublicKey: await cs.hpke.exportPublicKey(publicKey),
        parentHash: new Uint8Array(),
        unmergedLeaves: [],
      },
    }

    lastPathSecret = { nodeIndex: toNodeIndex(nodeIndex), secret: nextPathSecret, sendTo: resolution }
    pathSecrets.unshift(lastPathSecret)
  }
  return pathSecrets
}

export async function applyUpdatePath(
  mutableTree: RatchetTree,
  senderLeafIndex: LeafIndex,
  path: UpdatePath,
  h: Hash,
  isExternal: boolean = false,
): Promise<void> {
  // if this is an external commit, the leaf node did not exist prior
  if (!isExternal) {
    const leafToUpdate = mutableTree[leafToNodeIndex(senderLeafIndex)]

    if (leafToUpdate === undefined || leafToUpdate.nodeType === nodeTypes.parent)
      throw new InternalError("Leaf node not defined or is parent")

    const leafNodePublicKeyNotNew = constantTimeEqual(leafToUpdate.leaf.hpkePublicKey, path.leafNode.hpkePublicKey)

    if (leafNodePublicKeyNotNew)
      throw new ValidationError("Public key in the LeafNode is the same as the committer's current leaf node")
  }

  const pathNodePublicKeysExistInTree = path.nodes.some((node) =>
    mutableTree.some((treeNode) => {
      return treeNode?.nodeType === nodeTypes.parent
        ? constantTimeEqual(treeNode.parent.hpkePublicKey, node.hpkePublicKey)
        : false
    }),
  )

  if (pathNodePublicKeysExistInTree)
    throw new ValidationError("Public keys in the UpdatePath may not appear in a node of the new ratchet tree")

  const reverseFilteredDirectPath = filteredDirectPath(senderLeafIndex, mutableTree).reverse()

  mutableTree[leafToNodeIndex(senderLeafIndex)] = { nodeType: nodeTypes.leaf, leaf: path.leafNode }

  // need to call .slice here so as not to mutate the original
  const reverseUpdatePath = path.nodes.slice().reverse()

  if (reverseUpdatePath.length !== reverseFilteredDirectPath.length) {
    throw new ValidationError("Invalid length of UpdatePath")
  }

  for (const [level, nodeIndex] of reverseFilteredDirectPath.entries()) {
    const parentHash = await calculateParentHash(mutableTree, nodeIndex, h)

    mutableTree[nodeIndex] = {
      nodeType: nodeTypes.parent,
      parent: { hpkePublicKey: reverseUpdatePath[level]!.hpkePublicKey, unmergedLeaves: [], parentHash: parentHash[0] },
    }
  }

  const leafParentHash = await calculateParentHash(mutableTree, leafToNodeIndex(senderLeafIndex), h)

  if (!constantTimeEqual(leafParentHash[0], path.leafNode.parentHash))
    throw new ValidationError("Parent hash did not match the UpdatePath")
}

export function firstCommonAncestor(tree: RatchetTree, leafIndex: LeafIndex, senderLeafIndex: LeafIndex): NodeIndex {
  const fdp = filteredDirectPathAndCopathResolution(senderLeafIndex, tree)

  for (const { nodeIndex } of fdp) {
    if (isAncestor(leafToNodeIndex(leafIndex), nodeIndex, tree.length)) {
      return nodeIndex
    }
  }

  throw new ValidationError("Could not find common ancestor")
}

export function firstMatchAncestor(
  tree: RatchetTree,
  leafIndex: LeafIndex,
  senderLeafIndex: LeafIndex,
  path: UpdatePath,
): { nodeIndex: NodeIndex; resolution: NodeIndex[]; updateNode: UpdatePathNode | undefined } {
  const fdp = filteredDirectPathAndCopathResolution(senderLeafIndex, tree)

  for (const [n, { nodeIndex, resolution }] of fdp.entries()) {
    if (isAncestor(leafToNodeIndex(leafIndex), nodeIndex, tree.length)) {
      return { nodeIndex, resolution, updateNode: path.nodes[n] }
    }
  }

  throw new ValidationError("Could not find common ancestor")
}
