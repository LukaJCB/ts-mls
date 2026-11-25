import { hexToBytes } from "@noble/ciphers/utils.js"
import { getCiphersuiteImpl } from "../src/crypto/getCiphersuiteImpl.js"
import { CryptoVerificationError } from "../src/mlsError.js"
import { toPrivateKeyPath } from "../src/privateKeyPath.js"
import { ratchetTreeDecoder } from "../src/ratchetTree.js"
import { pathToRoot } from "../src/pathSecrets.js"
import { toNodeIndex } from "../src/treemath.js"
import { nodeTypes } from "../src/nodeType.js"
import vectors from "../test_vectors/treekem.json"

test.each([1, 3])("rejects a mismatched derived public key at node %i", async (nodeIndex) => {
  const impl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
  const vector = vectors[1]!
  const tree = ratchetTreeDecoder(hexToBytes(vector.ratchet_tree), 0)![0]
  const leaf = vector.leaves_private[0]!
  const initialSecret = leaf.path_secrets.find((ps) => ps.node === 1)!
  const secrets = await pathToRoot(tree, toNodeIndex(1), hexToBytes(initialSecret.path_secret), impl.kdf)

  // Both the decrypted node and its derived ancestor must match the advertised keys.
  const node = tree[nodeIndex]
  if (node?.nodeType !== nodeTypes.parent) throw new Error("Expected parent node")
  const replacement = await impl.hpke.generateKeyPair()
  tree[nodeIndex] = {
    ...node,
    parent: { ...node.parent, hpkePublicKey: await impl.hpke.exportPublicKey(replacement.publicKey) },
  }

  await expect(toPrivateKeyPath(secrets, leaf.index, impl, tree)).rejects.toThrow(
    new CryptoVerificationError("Derived public key does not match the ratchet tree"),
  )
})
