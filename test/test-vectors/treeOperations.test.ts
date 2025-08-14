import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import {
  addLeafNode,
  decodeRatchetTree,
  encodeRatchetTree,
  RatchetTree,
  removeLeafNode,
  updateLeafNode,
} from "../../src/ratchetTree"
import { hexToBytes } from "@noble/ciphers/utils"
import json from "../../test_vectors/tree-operations.json"
import { decodeProposal, Proposal } from "../../src/proposal"
import { treeHashRoot } from "../../src/treeHash"
import { toLeafIndex } from "../../src/treemath"

// How can there be a proposal with leaf_node_source = key_package in the test vectors?
// https://github.com/mlswg/mls-implementations/issues/195
for (const [index, x] of json.filter((_n, idx) => idx !== 2).entries()) {
  test(`tree-operations test vectors ${index}`, async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await treeOperationsTest(x, impl)
  })
}

type TreeOperationData = {
  proposal: string
  proposal_sender: number
  tree_after: string
  tree_before: string
  tree_hash_after: string
  tree_hash_before: string
}

async function treeOperationsTest(data: TreeOperationData, impl: CiphersuiteImpl) {
  const tree = decodeRatchetTree(hexToBytes(data.tree_before), 0)

  if (tree === undefined) throw new Error("could not decode tree")

  const hash = await treeHashRoot(tree[0], impl.hash)
  expect(hash).toStrictEqual(hexToBytes(data.tree_hash_before))

  const proposal = decodeProposal(hexToBytes(data.proposal), 0)
  if (proposal === undefined) throw new Error("could not decode proposal")

  const treeAfter = applyProposal(proposal[0], tree[0], data)

  if (treeAfter === undefined) throw new Error("Could not apply proposal: " + proposal[0].proposalType)

  expect(encodeRatchetTree(treeAfter)).toStrictEqual(hexToBytes(data.tree_after))

  const hashAfter = await treeHashRoot(treeAfter!, impl.hash)
  expect(hashAfter).toStrictEqual(hexToBytes(data.tree_hash_after))
}

function applyProposal(proposal: Proposal, tree: RatchetTree, data: TreeOperationData) {
  switch (proposal.proposalType) {
    case "add":
      return addLeafNode(tree, proposal.add.keyPackage.leafNode)[0]
    case "update":
      return updateLeafNode(tree, proposal.update.leafNode, toLeafIndex(data.proposal_sender))
    case "remove":
      return removeLeafNode(tree, toLeafIndex(proposal.remove.removed))
    case "psk":
    case "reinit":
    case "external_init":
    case "group_context_extensions":
  }
}
