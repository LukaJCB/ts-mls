import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { decodeRatchetTree, resolution } from "../../src/ratchetTree.js"
import { hexToBytes } from "@noble/ciphers/utils.js"
import json from "../../test_vectors/tree-validation.json"
import { treeHash } from "../../src/treeHash.js"
import { verifyLeafNodeSignature } from "../../src/leafNode.js"
import { nodeToLeafIndex, toNodeIndex } from "../../src/treemath.js"
import { verifyParentHashes } from "../../src/parentHash.js"
import { nodeTypes } from "../../src/nodeType.js"

test.concurrent.each(json.map((x, index) => [index, x]))(`tree-validation test vectors %i`, async (_index, x) => {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
  await treeOperationsTest(x, impl)
})

type TreeValidationData = {
  tree: string
  group_id: string
  tree_hashes: string[]
  resolutions: number[][]
}

async function treeOperationsTest(data: TreeValidationData, impl: CiphersuiteImpl) {
  const tree = decodeRatchetTree(hexToBytes(data.tree), 0)

  if (tree === undefined) throw new Error("could not decode tree")

  for (const [i, h] of data.tree_hashes.entries()) {
    const hash = await treeHash(tree[0], toNodeIndex(i), impl.hash)
    expect(hash).toStrictEqual(hexToBytes(h))
  }

  for (const [i, r] of data.resolutions.entries()) {
    const reso = resolution(tree[0], toNodeIndex(i))
    expect(reso).toStrictEqual(r)
  }

  expect(await verifyParentHashes(tree[0], impl.hash)).toBe(true)

  for (const [i, n] of tree[0].entries()) {
    if (n !== undefined) {
      if (n.nodeType === nodeTypes.leaf) {
        expect(
          await verifyLeafNodeSignature(
            n.leaf,
            hexToBytes(data.group_id),
            nodeToLeafIndex(toNodeIndex(i)),
            impl.signature,
          ),
        ).toBe(true)
      }
    }
  }
}
