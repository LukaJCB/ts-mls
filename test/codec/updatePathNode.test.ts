import { encodeUpdatePathNode, decodeUpdatePathNode, UpdatePathNode } from "../../src/updatePath"
import { createRoundtripTest } from "./roundtrip.js"

describe("UpdatePathNode roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeUpdatePathNode, decodeUpdatePathNode)

  test("roundtrips minimal", () => {
    const node: UpdatePathNode = {
      hpkePublicKey: new Uint8Array([1, 2, 3]),
      encryptedPathSecret: [],
    }
    roundtrip(node)
  })

  test("roundtrips nontrivial", () => {
    const node: UpdatePathNode = {
      hpkePublicKey: new Uint8Array([4, 5, 6, 7, 8]),
      encryptedPathSecret: [
        { ciphertext: new Uint8Array([9, 10, 11]), kemOutput: new Uint8Array([12, 13]) },
        { ciphertext: new Uint8Array([14, 15, 16, 17]), kemOutput: new Uint8Array([18, 19, 20]) },
      ],
    }
    roundtrip(node)
  })
})
