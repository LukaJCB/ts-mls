import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { Hash } from "./crypto/hash.js"
import { encryptWithLabel, PrivateKey } from "./crypto/hpke.js"
import { deriveSecret } from "./crypto/kdf.js"
import { groupContextEncoder, GroupContext } from "./groupContext.js"
import {
  decodeLeafNodeCommit,
  leafNodeEncoder,
  LeafNodeCommit,
  LeafNodeTBSCommit,
  signLeafNodeCommit,
} from "./leafNode.js"
import { calculateParentHash } from "./parentHash.js"
import {
  filteredDirectPath,
  filteredDirectPathAndCopathResolution,
  getHpkePublicKey,
  Node,
  RatchetTree,
} from "./ratchetTree.js"
import { treeHashRoot } from "./treeHash.js"
import { isAncestor, LeafIndex, leafToNodeIndex, NodeIndex } from "./treemath.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"
import { decodeHpkeCiphertext, hpkeCiphertextEncoder, HPKECiphertext } from "./hpkeCiphertext.js"
import { InternalError, ValidationError } from "./mlsError.js"

/** @public */
export interface UpdatePathNode {
  hpkePublicKey: Uint8Array
  encryptedPathSecret: HPKECiphertext[]
}

export const updatePathNodeEncoder: BufferEncoder<UpdatePathNode> = contramapBufferEncoders(
  [varLenDataEncoder, varLenTypeEncoder(hpkeCiphertextEncoder)],
  (node) => [node.hpkePublicKey, node.encryptedPathSecret] as const,
)

export const encodeUpdatePathNode: Encoder<UpdatePathNode> = encode(updatePathNodeEncoder)

export const decodeUpdatePathNode: Decoder<UpdatePathNode> = mapDecoders(
  [decodeVarLenData, decodeVarLenType(decodeHpkeCiphertext)],
  (hpkePublicKey, encryptedPathSecret) => ({ hpkePublicKey, encryptedPathSecret }),
)

/** @public */
export interface UpdatePath {
  leafNode: LeafNodeCommit
  nodes: UpdatePathNode[]
}

export const updatePathEncoder: BufferEncoder<UpdatePath> = contramapBufferEncoders(
  [leafNodeEncoder, varLenTypeEncoder(updatePathNodeEncoder)],
  (path) => [path.leafNode, path.nodes] as const,
)

export const encodeUpdatePath: Encoder<UpdatePath> = encode(updatePathEncoder)

export const decodeUpdatePath: Decoder<UpdatePath> = mapDecoders(
  [decodeLeafNodeCommit, decodeVarLenType(decodeUpdatePathNode)],
  (leafNode, nodes) => ({ leafNode, nodes }),
)

export interface PathSecret {
  nodeIndex: number
  secret: Uint8Array
  sendTo: number[]
}

export async function createUpdatePath(
  originalTree: RatchetTree,
  senderLeafIndex: LeafIndex,
  groupContext: GroupContext,
  signaturePrivateKey: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<[RatchetTree, UpdatePath, PathSecret[], PrivateKey]> {
  const originalLeafNode = originalTree[leafToNodeIndex(senderLeafIndex)]
  if (originalLeafNode === undefined || originalLeafNode.nodeType === "parent")
    throw new InternalError("Expected non-blank leaf node")

  const pathSecret = cs.rng.randomBytes(cs.kdf.size)

  const leafNodeSecret = await deriveSecret(pathSecret, "node", cs.kdf)
  const leafKeypair = await cs.hpke.deriveKeyPair(leafNodeSecret)

  const fdp = filteredDirectPathAndCopathResolution(senderLeafIndex, originalTree)

  const copy = originalTree.slice()

  const [ps, updatedTree]: [PathSecret[], RatchetTree] = await applyInitialTreeUpdate(
    fdp,
    pathSecret,
    senderLeafIndex,
    copy,
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
    groupId: groupContext.groupId,
    leafIndex: senderLeafIndex,
  }

  const updatedLeafNode = await signLeafNodeCommit(updatedLeafNodeTbs, signaturePrivateKey, cs.signature)

  treeWithHashes[leafToNodeIndex(senderLeafIndex)] = {
    nodeType: "leaf",
    leaf: updatedLeafNode,
  }

  const updatedTreeHash = await treeHashRoot(treeWithHashes, cs.hash)

  const updatedGroupContext: GroupContext = {
    ...groupContext,
    treeHash: updatedTreeHash,
    epoch: groupContext.epoch + 1n,
  }

  // we have to remove the leaf secret since we don't send it to anyone
  const pathSecrets = ps.slice(0, ps.length - 1).reverse()

  // we have to pass the old tree here since the receiver won't have the updated public keys yet
  const updatePathNodes: UpdatePathNode[] = await Promise.all(
    pathSecrets.map(encryptSecretsForPath(originalTree, treeWithHashes, updatedGroupContext, cs)),
  )

  const updatePath: UpdatePath = { leafNode: updatedLeafNode, nodes: updatePathNodes }

  return [treeWithHashes, updatePath, pathSecrets, leafKeypair.privateKey] as const
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
            encode(groupContextEncoder)(updatedGroupContext),
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
  tree: RatchetTree,
  cs: CiphersuiteImpl,
) {
  for (let x = fdp.length - 1; x >= 0; x--) {
    const { nodeIndex } = fdp[x]!
    const parentHash = await calculateParentHash(tree, nodeIndex, cs.hash)
    const currentNode = tree[nodeIndex]
    if (currentNode === undefined || currentNode.nodeType === "leaf")
      throw new InternalError("Expected non-blank parent node")
    const updatedNode: Node = { nodeType: "parent", parent: { ...currentNode.parent, parentHash: parentHash[0] } }
    tree[nodeIndex] = updatedNode
  }
  return tree
}

/**
 * Inserts new public keys from a single secret in the update path and returns the resulting tree along with the secrets along the path
 * Note that the path secrets are returned root to leaf
 */
async function applyInitialTreeUpdate(
  fdp: { resolution: number[]; nodeIndex: number }[],
  pathSecret: Uint8Array,
  senderLeafIndex: LeafIndex,
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

      tree[nodeIndex] = {
        nodeType: "parent",
        parent: {
          hpkePublicKey: await cs.hpke.exportPublicKey(publicKey),
          parentHash: new Uint8Array(),
          unmergedLeaves: [],
        },
      }

      return [[{ nodeIndex, secret: nextPathSecret, sendTo: resolution }, ...pathSecrets], tree]
    },
    Promise.resolve([[{ secret: pathSecret, nodeIndex: leafToNodeIndex(senderLeafIndex), sendTo: [] }], tree] as [
      PathSecret[],
      RatchetTree,
    ]),
  )
}

export async function applyUpdatePath(
  tree: RatchetTree,
  senderLeafIndex: LeafIndex,
  path: UpdatePath,
  h: Hash,
  isExternal: boolean = false,
): Promise<RatchetTree> {
  // if this is an external commit, the leaf node did not exist prior
  if (!isExternal) {
    const leafToUpdate = tree[leafToNodeIndex(senderLeafIndex)]

    if (leafToUpdate === undefined || leafToUpdate.nodeType === "parent")
      throw new InternalError("Leaf node not defined or is parent")

    const leafNodePublicKeyNotNew = constantTimeEqual(leafToUpdate.leaf.hpkePublicKey, path.leafNode.hpkePublicKey)

    if (leafNodePublicKeyNotNew)
      throw new ValidationError("Public key in the LeafNode is the same as the committer's current leaf node")
  }

  const pathNodePublicKeysExistInTree = path.nodes.some((node) =>
    tree.some((treeNode) => {
      return treeNode?.nodeType === "parent"
        ? constantTimeEqual(treeNode.parent.hpkePublicKey, node.hpkePublicKey)
        : false
    }),
  )

  if (pathNodePublicKeysExistInTree)
    throw new ValidationError("Public keys in the UpdatePath may not appear in a node of the new ratchet tree")

  const copy = tree.slice()

  copy[leafToNodeIndex(senderLeafIndex)] = { nodeType: "leaf", leaf: path.leafNode }

  const reverseFilteredDirectPath = filteredDirectPath(senderLeafIndex, tree).reverse()

  // need to call .slice here so as not to mutate the original
  const reverseUpdatePath = path.nodes.slice().reverse()

  if (reverseUpdatePath.length !== reverseFilteredDirectPath.length) {
    throw new ValidationError("Invalid length of UpdatePath")
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
    throw new ValidationError("Parent hash did not match the UpdatePath")

  return copy
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
