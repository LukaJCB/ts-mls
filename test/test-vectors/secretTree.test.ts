import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { hexToBytes } from "@noble/ciphers/utils"
import json from "../../test_vectors/secret-tree.json"
import { expandSenderDataKey, expandSenderDataNonce } from "../../src/sender"
import { createSecretTree, deriveKey, deriveNonce, ratchetUntil } from "../../src/secretTree"
import { leafToNodeIndex } from "../../src/treemath"

for (const [index, x] of json.entries()) {
  test(`secret-tree test vectors ${index}`, async () => {
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
}

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

  const tree = await createSecretTree(leaves.length, hexToBytes(encryptionSecret), impl.kdf)
  for (const [index, leaf] of leaves.entries()) {
    const nodeIndex = leafToNodeIndex(index)
    const handshakeSecret = tree[nodeIndex]!.handshake
    for (const gen of leaf) {
      const ratcheted = await ratchetUntil(handshakeSecret, gen.generation, 1000, impl.kdf)
      expect(ratcheted.generation).toBe(gen.generation)

      //handshake_key = handshake_ratchet_key_[i]_[generation]
      const handshakeKey = await deriveKey(ratcheted.secret, ratcheted.generation, impl)
      expect(handshakeKey).toStrictEqual(hexToBytes(gen.handshake_key))

      // handshake_nonce = handshake_ratchet_nonce_[i]_[generation]
      const handshakeNonce = await deriveNonce(ratcheted.secret, ratcheted.generation, impl)
      expect(handshakeNonce).toStrictEqual(hexToBytes(gen.handshake_nonce))
    }

    const applicationSecret = tree[nodeIndex]!.application
    for (const gen of leaf) {
      const ratcheted = await ratchetUntil(applicationSecret, gen.generation, 1000, impl.kdf)
      expect(ratcheted.generation).toBe(gen.generation)

      // application_key = application_ratchet_key_[i]_[generation]
      const applicationKey = await deriveKey(ratcheted.secret, ratcheted.generation, impl)
      expect(applicationKey).toStrictEqual(hexToBytes(gen.application_key))

      // application_nonce = application_ratchet_nonce_[i]_[generation]
      const applicationNonce = await deriveNonce(ratcheted.secret, ratcheted.generation, impl)
      expect(applicationNonce).toStrictEqual(hexToBytes(gen.application_nonce))
    }
  }
}
