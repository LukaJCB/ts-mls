import { describe, expect } from "vitest"
import { createSecretTree, consumeRatchet, ratchetToGeneration } from "../src/secretTree.js"
import { toLeafIndex, root } from "../src/treemath.js"
import { getCiphersuiteFromName } from "../src/crypto/ciphersuite.js"
import { defaultKeyRetentionConfig } from "../src/keyRetentionConfig.js"
import { ReuseGuard } from "../src/sender.js"
import { getCiphersuiteImpl } from "../src/index.js"
import { expandWithLabel } from "../src/crypto/kdf.js"
import { constantTimeEqual } from "../src/util/constantTimeCompare.js"

describe("SecretTree Deletion Schedule", () => {
  const impl = getCiphersuiteImpl(getCiphersuiteFromName("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"))

  test("should delete parent nodes when children are derived via consumeRatchet", async () => {
    const cs = await impl
    const leafWidth = 4
    const encryptionSecret = crypto.getRandomValues(new Uint8Array(32))
    const tree = createSecretTree(leafWidth, encryptionSecret)

    const rootIndex = root(leafWidth)
    expect(tree.intermediateNodes[rootIndex]).toBeDefined()

    // Derive leaf 0 (node index 0)
    const result0 = await consumeRatchet(tree, toLeafIndex(0), "application", cs)

    // Tree
    //             X
    //         X       X
    //       X   X   X   X
    // Node: 0 1 2 3 4 5 6
    // Leaf: 0   1   2   3

    // nodeIndex 0 should be the new SecretTreeNode
    // nodeIndex 1 & 3 are consumed
    // nodeIndex 2 is a leaf that isn't turned into a SecretTreeNode yet
    // nodeIndex 5 is an unconsumed intermediate node

    expect(result0.newTree.leafNodes[0]).toBeDefined()
    expect(Object.values(result0.newTree.leafNodes).length).toBe(1)

    expect(result0.newTree.intermediateNodes[2]).toBeDefined()
    expect(result0.newTree.intermediateNodes[5]).toBeDefined()
    expect(Object.values(result0.newTree.intermediateNodes).length).toBe(2)

    expect(result0.newTree.intermediateNodes[rootIndex]).toBeUndefined()
    expect(result0.newTree.intermediateNodes[1]).toBeUndefined()

    expect(result0.newTree.intermediateNodes[0]).toBeUndefined()

    expect(result0.consumed.some((b) => b === tree.intermediateNodes[rootIndex]!)).toBe(true)

    // since the secret is removed from the array we need to re-derive it to ensure it's the same in the consumed array
    const secret1 = await expandWithLabel(
      tree.intermediateNodes[rootIndex]!,
      "tree",
      new TextEncoder().encode("left"),
      cs.kdf.size,
      cs.kdf,
    )
    expect(result0.consumed.some((b) => constantTimeEqual(b, secret1))).toBe(true)

    // Derive leaf 3 (node index 6)
    const result3 = await consumeRatchet(result0.newTree, toLeafIndex(3), "proposal", cs)

    // Tree
    //             X
    //         X       X
    //       X   X   X   X
    // Node: 0 1 2 3 4 5 6
    // Leaf: 0   1   2   3

    // nodeIndex 0 & 6 should be SecretTreeNodes
    // nodeIndex 1, 3 & 5 are consumed
    // nodeIndex 2 & 4 are leaves that aren't turned into a SecretTreeNode yet

    expect(result3.newTree.leafNodes[0]).toBeDefined()
    expect(result3.newTree.leafNodes[6]).toBeDefined()
    expect(Object.values(result3.newTree.leafNodes).length).toBe(2)

    expect(result3.newTree.intermediateNodes[2]).toBeDefined()
    expect(result3.newTree.intermediateNodes[4]).toBeDefined()
    expect(Object.values(result3.newTree.intermediateNodes).length).toBe(2)

    expect(result3.newTree.intermediateNodes[rootIndex]).toBeUndefined()
    expect(result3.newTree.intermediateNodes[1]).toBeUndefined()
    expect(result3.newTree.intermediateNodes[5]).toBeUndefined()

    expect(result3.newTree.intermediateNodes[0]).toBeUndefined()
    expect(result3.newTree.intermediateNodes[6]).toBeUndefined()

    // 1 & 3 were consumed earlier so they we don't check for them here
    expect(result3.consumed.some((b) => b === result0.newTree.intermediateNodes[5]!)).toBe(true)

    // Derive leaf 2 (node index 4)
    const result2 = await consumeRatchet(result3.newTree, toLeafIndex(2), "application", cs)

    // Tree
    //             X
    //         X       X
    //       X   X   X   X
    // Node: 0 1 2 3 4 5 6
    // Leaf: 0   1   2   3

    // nodeIndex 0, 4 & 6 should be SecretTreeNodes
    // nodeIndex 1, 3 & 5 are consumed
    // nodeIndex 2 is leaf that isn't turned into a SecretTreeNode yet

    expect(result2.newTree.leafNodes[0]).toBeDefined()
    expect(result2.newTree.leafNodes[6]).toBeDefined()
    expect(result2.newTree.leafNodes[4]).toBeDefined()
    expect(Object.values(result2.newTree.leafNodes).length).toBe(3)

    expect(result2.newTree.intermediateNodes[2]).toBeDefined()
    expect(Object.values(result2.newTree.intermediateNodes).length).toBe(1)

    expect(result2.newTree.intermediateNodes[rootIndex]).toBeUndefined()
    expect(result2.newTree.intermediateNodes[1]).toBeUndefined()
    expect(result2.newTree.intermediateNodes[5]).toBeUndefined()
    expect(result2.newTree.intermediateNodes[4]).toBeUndefined()

    expect(result2.newTree.intermediateNodes[0]).toBeUndefined()
    expect(result2.newTree.intermediateNodes[6]).toBeUndefined()

    expect(result2.consumed.some((b) => b === result3.newTree.intermediateNodes[4]!)).toBe(true)
  })

  test("should delete parent nodes when children are derived via ratchetToGeneration", async () => {
    const cs = await impl
    const leafWidth = 4
    const encryptionSecret = new Uint8Array(32).fill(2)
    const tree = createSecretTree(leafWidth, encryptionSecret)

    const rootIndex = root(leafWidth)

    // Derive leaf 0 (node index 0) at generation 0
    const senderData = {
      leafIndex: 0,
      generation: 0,
      reuseGuard: new Uint8Array(4).fill(0) as ReuseGuard,
    }

    const result0 = await ratchetToGeneration(tree, senderData, "application", defaultKeyRetentionConfig, cs)

    // Tree
    //             X
    //         X       X
    //       X   X   X   X
    // Node: 0 1 2 3 4 5 6
    // Leaf: 0   1   2   3

    // nodeIndex 0 should be the new SecretTreeNode
    // nodeIndex 1 & 3 are consumed
    // nodeIndex 2 is a leaf that isn't turned into a SecretTreeNode yet
    // nodeIndex 5 is an unconsumed intermediate node

    expect(result0.newTree.leafNodes[0]).toBeDefined()
    expect(Object.values(result0.newTree.leafNodes).length).toBe(1)

    expect(result0.newTree.intermediateNodes[5]).toBeDefined()
    expect(result0.newTree.intermediateNodes[2]).toBeDefined()
    expect(Object.values(result0.newTree.intermediateNodes).length).toBe(2)

    expect(result0.newTree.intermediateNodes[rootIndex]).toBeUndefined()
    expect(result0.newTree.intermediateNodes[1]).toBeUndefined()

    expect(result0.consumed.some((b) => b === tree.intermediateNodes[rootIndex]!)).toBe(true)

    // since the secret is removed from the array we need to re-derive it to ensure it's the same in the consumed array
    const secret1 = await expandWithLabel(
      tree.intermediateNodes[rootIndex]!,
      "tree",
      new TextEncoder().encode("left"),
      cs.kdf.size,
      cs.kdf,
    )
    expect(result0.consumed.some((b) => constantTimeEqual(b, secret1))).toBe(true)

    // Derive leaf 3 (node index 6) at generation 0
    const senderData3 = {
      leafIndex: 3,
      generation: 0,
      reuseGuard: new Uint8Array(4).fill(0) as ReuseGuard,
    }
    const result3 = await ratchetToGeneration(
      result0.newTree,
      senderData3,
      "application",
      defaultKeyRetentionConfig,
      cs,
    )

    // Tree
    //             X
    //         X       X
    //       X   X   X   X
    // Node: 0 1 2 3 4 5 6
    // Leaf: 0   1   2   3

    // nodeIndex 0 & 6 should be SecretTreeNodes
    // nodeIndex 1, 3 & 5 are consumed
    // nodeIndex 2 & 4 are leaves that aren't turned into a SecretTreeNode yet

    expect(result3.newTree.leafNodes[0]).toBeDefined()
    expect(result3.newTree.leafNodes[6]).toBeDefined()
    expect(Object.values(result3.newTree.leafNodes).length).toBe(2)

    expect(result3.newTree.intermediateNodes[2]).toBeDefined()
    expect(result3.newTree.intermediateNodes[4]).toBeDefined()
    expect(Object.values(result3.newTree.intermediateNodes).length).toBe(2)

    expect(result3.newTree.intermediateNodes[rootIndex]).toBeUndefined()
    expect(result3.newTree.intermediateNodes[1]).toBeUndefined()
    expect(result3.newTree.intermediateNodes[5]).toBeUndefined()

    // 1 & 3 were consumed earlier so they we don't check for them here
    expect(result3.consumed.some((b) => b === result0.newTree.intermediateNodes[5]!)).toBe(true)

    // Derive leaf 2 (node index 4) at generation 5
    const senderData2 = {
      leafIndex: 2,
      generation: 5,
      reuseGuard: new Uint8Array(4).fill(0) as ReuseGuard,
    }
    const result2 = await ratchetToGeneration(
      result3.newTree,
      senderData2,
      "application",
      defaultKeyRetentionConfig,
      cs,
    )

    // Tree
    //             X
    //         X       X
    //       X   X   X   X
    // Node: 0 1 2 3 4 5 6
    // Leaf: 0   1   2   3

    // nodeIndex 0, 4 & 6 should be SecretTreeNodes
    // nodeIndex 1, 3 & 5 are consumed
    // nodeIndex 2 is leaf that isn't turned into a SecretTreeNode yet

    expect(result2.newTree.leafNodes[0]).toBeDefined()
    expect(result2.newTree.leafNodes[6]).toBeDefined()
    expect(result2.newTree.leafNodes[4]).toBeDefined()
    expect(Object.values(result2.newTree.leafNodes).length).toBe(3)

    expect(result2.newTree.intermediateNodes[2]).toBeDefined()

    expect(Object.values(result2.newTree.intermediateNodes).length).toBe(1)

    expect(result2.newTree.intermediateNodes[rootIndex]).toBeUndefined()
    expect(result2.newTree.intermediateNodes[1]).toBeUndefined()
    expect(result2.newTree.intermediateNodes[5]).toBeUndefined()
    expect(result2.newTree.intermediateNodes[4]).toBeUndefined()

    expect(result2.newTree.intermediateNodes[0]).toBeUndefined()
    expect(result2.newTree.intermediateNodes[6]).toBeUndefined()

    expect(result2.consumed.some((b) => b === result3.newTree.intermediateNodes[4]!)).toBe(true)

    // test if it still works if we go back in generations
    // Derive leaf 2 (node index 4) at generation 2
    const senderData2EarlierGen = {
      leafIndex: 2,
      generation: 2,
      reuseGuard: new Uint8Array(4).fill(0) as ReuseGuard,
    }
    const result2EarlierGen = await ratchetToGeneration(
      result2.newTree,
      senderData2EarlierGen,
      "application",
      defaultKeyRetentionConfig,
      cs,
    )

    // Tree
    //             X
    //         X       X
    //       X   X   X   X
    // Node: 0 1 2 3 4 5 6
    // Leaf: 0   1   2   3

    // nodeIndex 0, 4 & 6 should be SecretTreeNodes
    // nodeIndex 1, 3 & 5 are consumed
    // nodeIndex 2 is leaf that isn't turned into a SecretTreeNode yet

    expect(result2EarlierGen.newTree.leafNodes[0]).toBeDefined()
    expect(result2EarlierGen.newTree.leafNodes[6]).toBeDefined()
    expect(result2EarlierGen.newTree.leafNodes[4]).toBeDefined()

    expect(result2EarlierGen.newTree.intermediateNodes[2]).toBeDefined()

    expect(result2EarlierGen.newTree.intermediateNodes[rootIndex]).toBeUndefined()
    expect(result2EarlierGen.newTree.intermediateNodes[1]).toBeUndefined()
    expect(result2EarlierGen.newTree.intermediateNodes[5]).toBeUndefined()
    expect(result2EarlierGen.newTree.intermediateNodes[4]).toBeUndefined()

    expect(result2EarlierGen.newTree.intermediateNodes[0]).toBeUndefined()
    expect(result2EarlierGen.newTree.intermediateNodes[6]).toBeUndefined()

    // test if it still works if we go forward a lot in generations
    // Derive leaf 2 (node index 4) at generation 22
    const senderData2LaterGen = {
      leafIndex: 2,
      generation: 22,
      reuseGuard: new Uint8Array(4).fill(0) as ReuseGuard,
    }
    const result2LaterGen = await ratchetToGeneration(
      result2EarlierGen.newTree,
      senderData2LaterGen,
      "application",
      defaultKeyRetentionConfig,
      cs,
    )

    // Tree
    //             X
    //         X       X
    //       X   X   X   X
    // Node: 0 1 2 3 4 5 6
    // Leaf: 0   1   2   3

    // nodeIndex 0, 4 & 6 should be SecretTreeNodes
    // nodeIndex 1, 3 & 5 are consumed
    // nodeIndex 2 is leaf that isn't turned into a SecretTreeNode yet

    expect(result2LaterGen.newTree.leafNodes[0]).toBeDefined()
    expect(result2LaterGen.newTree.leafNodes[6]).toBeDefined()
    expect(result2LaterGen.newTree.leafNodes[4]).toBeDefined()

    expect(result2LaterGen.newTree.intermediateNodes[2]).toBeDefined()

    expect(result2LaterGen.newTree.intermediateNodes[rootIndex]).toBeUndefined()
    expect(result2LaterGen.newTree.intermediateNodes[1]).toBeUndefined()
    expect(result2LaterGen.newTree.intermediateNodes[5]).toBeUndefined()
    expect(result2LaterGen.newTree.intermediateNodes[4]).toBeUndefined()

    expect(result2LaterGen.newTree.intermediateNodes[0]).toBeUndefined()
    expect(result2LaterGen.newTree.intermediateNodes[6]).toBeUndefined()

    //consumed should include result2EarlierGen's secret
    expect(
      result2LaterGen.consumed.some((b) =>
        constantTimeEqual(result2EarlierGen.newTree.leafNodes[4]!.application.secret, b),
      ),
    ).toBe(true)
  })

  test("should delete parent nodes for larger tree (leafWidth 16)", async () => {
    const cs = await impl
    const leafWidth = 16
    const encryptionSecret = crypto.getRandomValues(new Uint8Array(32))
    const tree = createSecretTree(leafWidth, encryptionSecret)

    const rootIndex = root(leafWidth)
    expect(tree.intermediateNodes[rootIndex]).toBeDefined()

    // Derive leaf 0 (node index 0)
    const result0 = await consumeRatchet(tree, toLeafIndex(0), "application", cs)

    // Tree structure for leafWidth=16:
    //                                                     X
    //                             X                                               X
    //                 X                       X                       X                       X
    //           X           X           X           X           X           X           X           X
    //        X     X     X     X     X     X     X     X     X     X     X     X     X     X     X     X
    // Nodes: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
    // Leafs: 0     1     2     3     4     5     6     7     8     9     10    11    12    13    14    15

    // nodeIndex 0 should be SecretTreeNode
    // nodeIndex 1, 3, 7 & 15 are consumed
    // nodeIndex 2 is leaf that isn't turned into a SecretTreeNode yet
    // nodeIndex 5, 11 & 23 are unconsumed intermediate nodes

    expect(result0.newTree.leafNodes[0]).toBeDefined()
    expect(Object.values(result0.newTree.leafNodes).length).toBe(1)

    expect(result0.newTree.intermediateNodes[23]).toBeDefined()
    expect(result0.newTree.intermediateNodes[11]).toBeDefined()
    expect(result0.newTree.intermediateNodes[5]).toBeDefined()
    expect(result0.newTree.intermediateNodes[2]).toBeDefined()
    expect(Object.values(result0.newTree.intermediateNodes).length).toBe(4)

    expect(result0.consumed.some((b) => b === tree.intermediateNodes[rootIndex]!)).toBe(true)

    // since the secret is removed from the array we need to re-derive it to ensure it's the same in the consumed array
    const secret7 = await expandWithLabel(
      tree.intermediateNodes[rootIndex]!,
      "tree",
      new TextEncoder().encode("left"),
      cs.kdf.size,
      cs.kdf,
    )
    expect(result0.consumed.some((b) => constantTimeEqual(b, secret7))).toBe(true)

    const secret3 = await expandWithLabel(secret7, "tree", new TextEncoder().encode("left"), cs.kdf.size, cs.kdf)
    expect(result0.consumed.some((b) => constantTimeEqual(b, secret3))).toBe(true)

    // Derive leaf 15 (node index 30)
    const result15 = await consumeRatchet(result0.newTree, toLeafIndex(15), "proposal", cs)

    //                                                     X
    //                             X                                               X
    //                 X                       X                       X                       X
    //           X           X           X           X           X           X           X           X
    //        X     X     X     X     X     X     X     X     X     X     X     X     X     X     X     X
    // Nodes: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
    // Leafs: 0     1     2     3     4     5     6     7     8     9     10    11    12    13    14    15

    // nodeIndex 0, 30 should be SecretTreeNodes
    // nodeIndex 1, 3, 7, 15, 23, 27, 29 are consumed
    // nodeIndex 2 & 28 is leaf that isn't turned into a SecretTreeNode yet
    // nodeIndex 5, 11 & 19, 25 are unconsumed intermediate nodes

    expect(result15.newTree.leafNodes[0]).toBeDefined()
    expect(result15.newTree.leafNodes[30]).toBeDefined()
    expect(Object.values(result15.newTree.leafNodes).length).toBe(2)

    expect(result15.newTree.intermediateNodes[5]).toBeDefined()
    expect(result15.newTree.intermediateNodes[11]).toBeDefined()
    expect(result15.newTree.intermediateNodes[19]).toBeDefined()
    expect(result15.newTree.intermediateNodes[25]).toBeDefined()

    expect(result15.newTree.intermediateNodes[28]).toBeDefined()
    expect(result15.newTree.intermediateNodes[2]).toBeDefined()
    expect(Object.values(result15.newTree.intermediateNodes).length).toBe(6)

    expect(result15.consumed.some((b) => b === result0.newTree.intermediateNodes[23]!)).toBe(true)

    const secret27 = await expandWithLabel(
      result0.newTree.intermediateNodes[23]!,
      "tree",
      new TextEncoder().encode("right"),
      cs.kdf.size,
      cs.kdf,
    )
    expect(result15.consumed.some((b) => constantTimeEqual(b, secret27))).toBe(true)

    const secret29 = await expandWithLabel(secret27, "tree", new TextEncoder().encode("right"), cs.kdf.size, cs.kdf)
    expect(result15.consumed.some((b) => constantTimeEqual(b, secret29))).toBe(true)

    // Derive leaf 7 (node index 14)
    const result7 = await consumeRatchet(result15.newTree, toLeafIndex(7), "application", cs)

    //                                                     X
    //                             X                                               X
    //                 X                       X                       X                       X
    //           X           X           X           X           X           X           X           X
    //        X     X     X     X     X     X     X     X     X     X     X     X     X     X     X     X
    // Nodes: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
    // Leafs: 0     1     2     3     4     5     6     7     8     9     10    11    12    13    14    15

    // nodeIndex 0, 14, 30 should be SecretTreeNodes
    // nodeIndex 1, 3, 7, 11, 13, 15, 23, 27, 29 are consumed
    // nodeIndex 2, 12 & 28 is leaf that isn't turned into a SecretTreeNode yet
    // nodeIndex 5, 9, 19, 25 are unconsumed intermediate nodes

    expect(result7.newTree.leafNodes[0]).toBeDefined()
    expect(result7.newTree.leafNodes[14]).toBeDefined()
    expect(result7.newTree.leafNodes[30]).toBeDefined()
    expect(Object.values(result7.newTree.leafNodes).length).toBe(3)

    expect(result7.newTree.intermediateNodes[2]).toBeDefined()
    expect(result7.newTree.intermediateNodes[12]).toBeDefined()
    expect(result7.newTree.intermediateNodes[28]).toBeDefined()

    expect(result7.newTree.intermediateNodes[5]).toBeDefined()
    expect(result7.newTree.intermediateNodes[9]).toBeDefined()
    expect(result7.newTree.intermediateNodes[19]).toBeDefined()
    expect(result7.newTree.intermediateNodes[25]).toBeDefined()
    expect(Object.values(result7.newTree.intermediateNodes).length).toBe(7)

    expect(result7.consumed.some((b) => b === result15.newTree.intermediateNodes[11]!)).toBe(true)

    const secret13 = await expandWithLabel(
      result15.newTree.intermediateNodes[11]!,
      "tree",
      new TextEncoder().encode("right"),
      cs.kdf.size,
      cs.kdf,
    )
    expect(result7.consumed.some((b) => constantTimeEqual(b, secret13))).toBe(true)

    // Derive leaf 4 (node index 8)
    const result4 = await consumeRatchet(result7.newTree, toLeafIndex(4), "application", cs)

    //                                                     X
    //                             X                                               X
    //                 X                       X                       X                       X
    //           X           X           X           X           X           X           X           X
    //        X     X     X     X     X     X     X     X     X     X     X     X     X     X     X     X
    // Nodes: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
    // Leafs: 0     1     2     3     4     5     6     7     8     9     10    11    12    13    14    15

    // nodeIndex 0, 8, 14, 30 should be SecretTreeNodes
    // nodeIndex 1, 3, 7, 9, 11, 13, 15, 23, 27, 29 are consumed
    // nodeIndex 2, 10, 12 & 28 is leaf that isn't turned into a SecretTreeNode yet
    // nodeIndex 5, 19, 25 are unconsumed intermediate nodes

    expect(result4.newTree.leafNodes[0]).toBeDefined()
    expect(result4.newTree.leafNodes[8]).toBeDefined()
    expect(result4.newTree.leafNodes[14]).toBeDefined()
    expect(result4.newTree.leafNodes[30]).toBeDefined()
    expect(Object.values(result4.newTree.leafNodes).length).toBe(4)

    expect(result4.newTree.intermediateNodes[2]).toBeDefined()
    expect(result4.newTree.intermediateNodes[10]).toBeDefined()
    expect(result4.newTree.intermediateNodes[12]).toBeDefined()
    expect(result4.newTree.intermediateNodes[28]).toBeDefined()

    expect(result4.newTree.intermediateNodes[5]).toBeDefined()
    expect(result4.newTree.intermediateNodes[19]).toBeDefined()
    expect(result4.newTree.intermediateNodes[25]).toBeDefined()
    expect(Object.values(result4.newTree.intermediateNodes).length).toBe(7)

    expect(result4.consumed.some((b) => b === result7.newTree.intermediateNodes[9]!)).toBe(true)

    // Derive leaf 6 (node index 12)
    const result6 = await consumeRatchet(result4.newTree, toLeafIndex(6), "application", cs)

    //                                                     X
    //                             X                                               X
    //                 X                       X                       X                       X
    //           X           X           X           X           X           X           X           X
    //        X     X     X     X     X     X     X     X     X     X     X     X     X     X     X     X
    // Nodes: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
    // Leafs: 0     1     2     3     4     5     6     7     8     9     10    11    12    13    14    15

    // nodeIndex 0, 8, 12, 14, 30 should be SecretTreeNodes
    // nodeIndex 1, 3, 7, 9, 11, 13, 15, 23, 27, 29 are consumed
    // nodeIndex 2, 10 & 28 is leaf that isn't turned into a SecretTreeNode yet
    // nodeIndex 5, 19, 25 are unconsumed intermediate nodes

    expect(result6.newTree.leafNodes[0]).toBeDefined()
    expect(result6.newTree.leafNodes[8]).toBeDefined()
    expect(result6.newTree.leafNodes[12]).toBeDefined()
    expect(result6.newTree.leafNodes[14]).toBeDefined()
    expect(result6.newTree.leafNodes[30]).toBeDefined()
    expect(Object.values(result6.newTree.leafNodes).length).toBe(5)

    expect(result6.newTree.intermediateNodes[2]).toBeDefined()
    expect(result6.newTree.intermediateNodes[10]).toBeDefined()
    expect(result6.newTree.intermediateNodes[28]).toBeDefined()

    expect(result6.newTree.intermediateNodes[5]).toBeDefined()
    expect(result6.newTree.intermediateNodes[19]).toBeDefined()
    expect(result6.newTree.intermediateNodes[25]).toBeDefined()
    expect(Object.values(result6.newTree.intermediateNodes).length).toBe(6)

    expect(result6.consumed.some((b) => b === result4.newTree.intermediateNodes[12]!)).toBe(true)
  })
})
