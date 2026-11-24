import { InternalError } from "../src/mlsError.js"
import { directPath, toNodeIndex } from "../src/treemath.js"

describe("directPath", () => {
  test.concurrent.each([
    { nodeIndex: 3, leafWidth: 2 },
    { nodeIndex: 4, leafWidth: 2 },
    { nodeIndex: 5, leafWidth: 3 },
    { nodeIndex: -1, leafWidth: 2 },
    { nodeIndex: 0, leafWidth: 0 },
  ])("rejects node $nodeIndex in a tree with $leafWidth leaves", ({ nodeIndex, leafWidth }) => {
    expect(() => directPath(toNodeIndex(nodeIndex), leafWidth)).toThrow(new InternalError("node index out of bounds"))
  })

  test.concurrent.each([
    { nodeIndex: 0, leafWidth: 1, expected: [] },
    { nodeIndex: 1, leafWidth: 2, expected: [] },
    { nodeIndex: 0, leafWidth: 2, expected: [1] },
    { nodeIndex: 2, leafWidth: 2, expected: [1] },
    { nodeIndex: 4, leafWidth: 3, expected: [5, 3] },
  ])("returns the path for node $nodeIndex in a tree with $leafWidth leaves", ({ nodeIndex, leafWidth, expected }) => {
    expect(directPath(toNodeIndex(nodeIndex), leafWidth)).toEqual(expected)
  })
})
