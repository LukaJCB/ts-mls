import {
  CiphersuiteId,
  CiphersuiteImpl,
  getCiphersuiteFromId,
  getCiphersuiteImpl,
  getCiphersuiteNameFromId,
} from "../../src/crypto/ciphersuite"
import { decodeRatchetTree, getHpkePublicKey, RatchetTree } from "../../src/ratchetTree"
import { hexToBytes } from "@noble/ciphers/utils"
import json from "../../test_vectors/treekem.json"
import { applyUpdatePath, createUpdatePath, decodeUpdatePath, UpdatePath } from "../../src/updatePath"
import { GroupContext } from "../../src/groupContext"
import { treeHashRoot } from "../../src/treeHash"
import { deriveSecret } from "../../src/crypto/kdf"
import { leafToNodeIndex } from "../../src/treemath"
import {
  applyUpdatePathSecret,
  getCommitSecret,
  NodeSecrets,
  PrivateKeyPath,
  toPrivateKeyPath,
} from "../../src/clientState"
import { hpkeKeysMatch } from "../crypto/keyMatch"

for (const [index, x] of json.entries()) {
  test(`treekem test vectors ${index}`, async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await treekemTest(x, impl)
  })
}

interface TreeKEMState {
  cipher_suite: number
  confirmed_transcript_hash: string
  epoch: number
  group_id: string
  leaves_private: LeafPrivateState[]
  ratchet_tree: string
  update_paths: UpdatePathState[]
}
interface LeafPrivateState {
  encryption_priv: string
  signature_priv: string
  index: number
  path_secrets: PathSecretState[]
}

interface PathSecretState {
  node: number
  path_secret: string
}

interface UpdatePathState {
  sender: number
  commit_secret: string
  path_secrets: (string | null)[]
  tree_hash_after: string
  update_path: string
}

async function treekemTest(data: TreeKEMState, impl: CiphersuiteImpl) {
  const tree = decodeRatchetTree(hexToBytes(data.ratchet_tree), 0)

  if (tree === undefined) throw new Error("could not decode tree")

  const th = await treeHashRoot(tree[0], impl.hash)

  const gc: GroupContext = {
    version: "mls10",
    cipherSuite: getCiphersuiteNameFromId(data.cipher_suite as CiphersuiteId),
    groupId: hexToBytes(data.group_id),
    epoch: BigInt(data.epoch),
    treeHash: th,
    confirmedTranscriptHash: hexToBytes(data.confirmed_transcript_hash),
    extensions: [],
  }

  const privatePaths = await getPrivatePaths(data, impl)

  await testTreeKeys(data, tree, impl)

  for (const path of data.update_paths) {
    const updatePath = decodeUpdatePath(hexToBytes(path.update_path), 0)

    if (updatePath === undefined) throw new Error("could not decode updatepath")

    const updatedTree = await applyUpdatePath(tree[0], path.sender, updatePath[0], impl.hash)

    const th = await treeHashRoot(updatedTree, impl.hash)

    expect(th).toStrictEqual(hexToBytes(path.tree_hash_after))

    const updatedGroupContext = { ...gc, treeHash: th }

    const senderLeafState = data.leaves_private.find((lp) => lp.index === path.sender)
    if (senderLeafState === undefined) {
      throw new Error("Could not find leaf for sender")
    }
    const [t, newUpdatePath, newSecrets] = await createUpdatePath(
      updatedTree,
      path.sender,
      updatedGroupContext,
      hexToBytes(senderLeafState.signature_priv),
      impl,
    )

    const rootSecret = newSecrets.slice().pop()!
    const newCommitSecret = await deriveSecret(rootSecret.secret, "path", impl.kdf)
    const newGroupContext = { ...gc, treeHash: await treeHashRoot(t, impl.hash), epoch: gc.epoch + 1n }

    for (const pp of privatePaths) {
      if (pp.leafIndex === path.sender) {
        expect(path.path_secrets[pp.leafIndex]).toBeNull
      } else {
        await testCommitSecret(tree, pp, path, updatedGroupContext, updatePath[0], impl)

        await testNewUpdatePath(tree, pp, path, newGroupContext, newUpdatePath, impl, newCommitSecret)
      }
    }
  }
}

async function testNewUpdatePath(
  tree: [RatchetTree, number],
  pp: PrivateKeyPath,
  path: UpdatePathState,
  newGroupContext: GroupContext,
  newUpdatePath: UpdatePath,
  impl: CiphersuiteImpl,
  newCommitSecret: Uint8Array,
) {
  const secret = await applyUpdatePathSecret(tree[0], pp, path.sender, newGroupContext, newUpdatePath, [], impl)

  const commitSecret = await getCommitSecret(tree[0], secret.nodeIndex, secret.pathSecret, impl.kdf)

  expect(commitSecret).toStrictEqual(newCommitSecret)
}

async function testCommitSecret(
  tree: [RatchetTree, number],
  pp: PrivateKeyPath,
  path: UpdatePathState,
  updatedGroupContext: GroupContext,
  updatePath: UpdatePath,
  impl: CiphersuiteImpl,
) {
  const privateP = await applyUpdatePathSecret(tree[0], pp, path.sender, updatedGroupContext, updatePath, [], impl)

  expect(privateP.pathSecret).toStrictEqual(hexToBytes(path.path_secrets[pp.leafIndex]!))

  const commitSecret = await getCommitSecret(tree[0], privateP.nodeIndex, privateP.pathSecret, impl.kdf)

  expect(commitSecret).toStrictEqual(hexToBytes(path.commit_secret))
}

async function getPrivatePaths(data: TreeKEMState, impl: CiphersuiteImpl): Promise<PrivateKeyPath[]> {
  return await Promise.all(
    data.leaves_private.map(async (leaf) => {
      const nodeSecrets: NodeSecrets = leaf.path_secrets.reduce(
        (acc, ps) => ({ ...acc, [ps.node]: hexToBytes(ps.path_secret) }),
        {},
      )

      const pks = await toPrivateKeyPath(nodeSecrets, leaf.index, impl)

      return {
        ...pks,
        privateKeys: { ...pks.privateKeys, [leafToNodeIndex(leaf.index)]: hexToBytes(leaf.encryption_priv) },
      }
    }),
  )
}

async function testTreeKeys(data: TreeKEMState, tree: [RatchetTree, number], impl: CiphersuiteImpl) {
  for (const leaf of data.leaves_private) {
    const nodeSecrets: NodeSecrets = leaf.path_secrets.reduce(
      (acc, ps) => ({ ...acc, [ps.node]: hexToBytes(ps.path_secret) }),
      {},
    )

    const node = tree[0][leafToNodeIndex(leaf.index)]
    if (node === undefined || node.nodeType === "parent") throw new Error("No leaf found at leaf index")

    expect(await hpkeKeysMatch(node.leaf.hpkePublicKey, hexToBytes(leaf.encryption_priv), impl.hpke)).toBe(true)

    for (const [nodeIndex, pathSecret] of Object.entries(nodeSecrets)) {
      const s = await deriveSecret(pathSecret, "node", impl.kdf)
      const { publicKey } = await impl.hpke.deriveKeyPair(s)

      const node = tree[0][Number(nodeIndex)]
      if (node === undefined) throw new Error("No node found at node index")

      expect(getHpkePublicKey(node)).toStrictEqual(await impl.hpke.exportPublicKey(publicKey))
    }
  }
}
