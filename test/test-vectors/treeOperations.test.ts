import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import {
  addLeafNode,
  decodeRatchetTree,
  encodeRatchetTree,
  RatchetTree,
  removeLeafNode,
  updateLeafNode,
} from "../../src/ratchetTree.js"
import { hexToBytes } from "@noble/ciphers/utils.js"
import json from "../../test_vectors/tree-operations.json"
import { decodeProposal, isDefaultProposal, Proposal } from "../../src/proposal.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { treeHashRoot } from "../../src/treeHash.js"
import { toLeafIndex } from "../../src/treemath.js"

test.concurrent.each(json.map((x, index) => [index, x]))(`tree-operations test vectors %i`, async (_index, x) => {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
  await treeOperationsTest(x, impl)
})

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

  const hashAfter = await treeHashRoot(treeAfter, impl.hash)
  expect(hashAfter).toStrictEqual(hexToBytes(data.tree_hash_after))
}

function applyProposal(proposal: Proposal, tree: RatchetTree, data: TreeOperationData) {
  if (!isDefaultProposal(proposal)) return tree

  switch (proposal.proposalType) {
    case defaultProposalTypes.add:
      return addLeafNode(tree, proposal.add.keyPackage.leafNode)[0]
    case defaultProposalTypes.update:
      return updateLeafNode(tree, proposal.update.leafNode, toLeafIndex(data.proposal_sender))
    case defaultProposalTypes.remove:
      return removeLeafNode(tree, toLeafIndex(proposal.remove.removed))
    case defaultProposalTypes.psk:
    case defaultProposalTypes.reinit:
    case defaultProposalTypes.external_init:
    case defaultProposalTypes.group_context_extensions:
      return tree
  }

  return tree
}
