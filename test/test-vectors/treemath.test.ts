import json from "../../test_vectors/tree-math.json"
import { left, nodeWidth, parent, right, root, sibling, toNodeIndex } from "../../src/treemath"
import { InternalError } from "../../src/mlsError"

for (const [index, x] of json.entries()) {
  test(`tree math test vectors ${index}`, () => {
    treemathTest(x)
  })
}

function treemathTest(t: {
  n_leaves: number
  n_nodes: number
  root: number
  left: (number | null)[]
  right: (number | null)[]
  parent: (number | null)[]
  sibling: (number | null)[]
}) {
  //n_nodes is the number of nodes in the tree with n_leaves leaves
  expect(nodeWidth(t.n_leaves)).toBe(t.n_nodes)
  //root is the root node index of the tree
  expect(root(t.n_leaves)).toBe(t.root)

  //left[i] is the node index of the left child of the node with index i in a tree with n_leaves leaves
  for (const [i, expected] of t.left.entries()) {
    const leftFn = () => left(toNodeIndex(i))
    if (expected != null) {
      expect(leftFn()).toBe(expected)
    } else {
      expect(leftFn).toThrow(InternalError)
    }
  }

  //right[i] is the node index of the right child of the node with index i in a tree with n_leaves leaves
  for (const [i, expected] of t.right.entries()) {
    const rightFn = () => right(toNodeIndex(i))
    if (expected != null) {
      expect(rightFn()).toBe(expected)
    } else {
      expect(rightFn).toThrow(InternalError)
    }
  }

  //parent[i] is the node index of the parent of the node with index i in a tree with n_leaves leaves
  for (const [i, expected] of t.parent.entries()) {
    const parentFn = () => parent(toNodeIndex(i), t.n_leaves)
    if (expected != null) {
      expect(parentFn()).toBe(expected)
    } else {
      expect(parentFn).toThrow(InternalError)
    }
  }

  //sibling[i] is the node index of the sibling of the node with index i in a tree with n_leaves leaves
  for (const [i, expected] of t.sibling.entries()) {
    const siblingFn = () => sibling(toNodeIndex(i), t.n_leaves)
    if (expected != null) {
      expect(siblingFn()).toBe(expected)
    } else {
      expect(siblingFn).toThrow(InternalError)
    }
  }
}
