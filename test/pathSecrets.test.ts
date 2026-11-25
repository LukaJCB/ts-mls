import { getCiphersuiteImpl } from "../src/crypto/getCiphersuiteImpl.js"
import { deriveSecret } from "../src/crypto/kdf.js"
import { nodeTypes } from "../src/nodeType.js"
import { derivePathSecrets, getCommitSecret } from "../src/pathSecrets.js"
import { toPrivateKeyPath } from "../src/privateKeyPath.js"
import { RatchetTree } from "../src/ratchetTree.js"
import { toNodeIndex } from "../src/treemath.js"

test.each([
  ["a blank root", 11],
  ["a blank intermediate ancestor", 7],
])("derives the commit secret after the last UpdatePath node with %s", async (_description, lastNodeIndex) => {
  const impl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
  const initialSecret = new Uint8Array(impl.kdf.size).fill(1)
  const lastSecret = await deriveSecret(initialSecret, "path", impl.kdf)
  const expectedCommitSecret = await deriveSecret(lastSecret, "path", impl.kdf)
  const expectedSecrets = { [9]: initialSecret, [lastNodeIndex]: lastSecret }
  const tree: RatchetTree = Array.from({ length: 15 }, () => undefined)

  // Structural ancestors of node 9 are 11 and 7. Only one is populated.
  for (const [index, secret] of Object.entries(expectedSecrets)) {
    const { publicKey } = await impl.hpke.deriveKeyPair(await deriveSecret(secret, "node", impl.kdf))
    tree[Number(index)] = {
      nodeType: nodeTypes.parent,
      parent: {
        hpkePublicKey: await impl.hpke.exportPublicKey(publicKey),
        parentHash: new Uint8Array(),
        unmergedLeaves: [],
      },
    }
  }

  const { pathSecrets, commitSecret } = await derivePathSecrets(tree, toNodeIndex(9), initialSecret, impl.kdf)
  expect(pathSecrets).toStrictEqual(expectedSecrets)
  expect(commitSecret).toStrictEqual(expectedCommitSecret)
  expect(await getCommitSecret(tree, toNodeIndex(9), initialSecret, impl.kdf)).toStrictEqual(expectedCommitSecret)

  const privatePath = await toPrivateKeyPath(pathSecrets, 4, impl, tree)
  expect(Object.keys(privatePath.privateKeys)).toStrictEqual(Object.keys(expectedSecrets))
})
