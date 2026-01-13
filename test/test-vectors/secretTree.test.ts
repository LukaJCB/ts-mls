import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { hexToBytes } from "@noble/ciphers/utils.js"
import json from "../../test_vectors/secret-tree.json"
import { expandSenderDataKey, expandSenderDataNonce, ReuseGuard } from "../../src/sender.js"
import { createSecretTree, ratchetToGeneration } from "../../src/secretTree.js"
import { toLeafIndex } from "../../src/treemath.js"
import { defaultKeyRetentionConfig } from "../../src/keyRetentionConfig.js"
import { contentTypes } from "../../src/contentType.js"

test.concurrent.each(json.map((x, index) => [index, x]))(`secret-tree test vectors %i`, async (_index, x) => {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
  await testSecretTree(
    x.sender_data.sender_data_secret,
    x.sender_data.ciphertext,
    x.sender_data.key,
    x.sender_data.nonce,
    x.encryption_secret,
    x.leaves,
    impl,
  )
})

type Leaf = {
  generation: number
  handshake_key: string
  handshake_nonce: string
  application_key: string
  application_nonce: string
}

async function testSecretTree(
  senderSecret: string,
  ciphertext: string,
  key: string,
  nonce: string,
  encryptionSecret: string,
  leaves: Leaf[][],
  impl: CiphersuiteImpl,
) {
  // key == sender_data_key(sender_data_secret, ciphertext)
  const derivedKey = await expandSenderDataKey(impl, hexToBytes(senderSecret), hexToBytes(ciphertext))
  expect(derivedKey).toStrictEqual(hexToBytes(key))

  //nonce == sender_data_nonce(sender_data_secret, ciphertext)
  const derivedNonce = await expandSenderDataNonce(impl, hexToBytes(senderSecret), hexToBytes(ciphertext))
  expect(derivedNonce).toStrictEqual(hexToBytes(nonce))

  let tree = createSecretTree(leaves.length, hexToBytes(encryptionSecret))
  for (const [index, leaf] of leaves.entries()) {
    const leafIndex = toLeafIndex(index)
    for (const gen of leaf) {
      const senderData = { leafIndex, generation: gen.generation, reuseGuard: new Uint8Array(4) as ReuseGuard }
      const app = await ratchetToGeneration(tree, senderData, contentTypes.application, defaultKeyRetentionConfig, impl)

      expect(app.generation).toBe(gen.generation)
      // application_key = application_ratchet_key_[i]_[generation]
      expect(app.key).toStrictEqual(hexToBytes(gen.application_key))
      // application_nonce = application_ratchet_nonce_[i]_[generation]
      expect(app.nonce).toStrictEqual(hexToBytes(gen.application_nonce))

      const handshake = await ratchetToGeneration(
        app.newTree,
        senderData,
        contentTypes.commit,
        defaultKeyRetentionConfig,
        impl,
      )

      expect(handshake.generation).toBe(gen.generation)
      //handshake_key = handshake_ratchet_key_[i]_[generation]
      expect(handshake.key).toStrictEqual(hexToBytes(gen.handshake_key))
      // handshake_nonce = handshake_ratchet_nonce_[i]_[generation]
      expect(handshake.nonce).toStrictEqual(hexToBytes(gen.handshake_nonce))
      tree = handshake.newTree
    }
  }
}
