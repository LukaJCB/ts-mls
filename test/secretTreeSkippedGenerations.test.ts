import { decode } from "../src/codec/tlsDecoder.js"
import { encode } from "../src/codec/tlsEncoder.js"
import { ContentTypeValue, contentTypes } from "../src/contentType.js"
import { CiphersuiteName, ciphersuites } from "../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../src/crypto/getCiphersuiteImpl.js"
import { expandWithLabel } from "../src/crypto/kdf.js"
import { defaultKeyRetentionConfig } from "../src/keyRetentionConfig.js"
import {
  appendSecretTreeValues,
  createSecretTree,
  ratchetToGeneration,
  secretTreeDecoder,
  secretTreeEncoder,
} from "../src/secretTree.js"
import { ReuseGuard, SenderData } from "../src/sender.js"
import { fastEqual, zeroOutUint8Array } from "../src/util/byteArray.js"

const SUITE: CiphersuiteName = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"

function senderData(message: Pick<SenderData, "generation" | "reuseGuard">): SenderData {
  return { leafIndex: 0, generation: message.generation, reuseGuard: message.reuseGuard }
}

async function setup(cipherSuite: CiphersuiteName, contentType: ContentTypeValue) {
  const cs = await getCiphersuiteImpl(cipherSuite)
  const encryptionSecret = cs.rng.randomBytes(cs.kdf.size)
  let senderTree = createSecretTree(1, encryptionSecret.slice())
  const receiverTree = createSecretTree(1, encryptionSecret.slice())
  const ratchet: "application" | "handshake" = contentType === contentTypes.application ? "application" : "handshake"
  const rootSecret = await expandWithLabel(encryptionSecret, ratchet, new Uint8Array(), cs.kdf.size, cs.kdf)
  const ratchetSecrets = [rootSecret]
  const messages: Awaited<ReturnType<typeof ratchetToGeneration>>[] = []
  for (let generation = 0; generation < 3; generation++) {
    const result = await ratchetToGeneration(
      senderTree,
      { leafIndex: 0, generation, reuseGuard: new Uint8Array([generation + 1, 2, 3, 4]) as ReuseGuard },
      contentType,
      defaultKeyRetentionConfig,
      cs,
    )
    messages.push(result)
    senderTree = result.newTree
    if (generation < 2) ratchetSecrets.push(senderTree.leafNodes[0]![ratchet].secret)
  }
  return { cs, receiverTree, ratchet, ratchetSecrets, messages }
}

test.concurrent.each(Object.keys(ciphersuites))(
  "skipped generations retain only message keys and nonces %s",
  async (cs) => {
    for (const contentType of [contentTypes.application, contentTypes.proposal]) {
      const {
        cs: impl,
        receiverTree,
        ratchet,
        ratchetSecrets,
        messages,
      } = await setup(cs as CiphersuiteName, contentType)
      const latest = messages[2]!
      const received = await ratchetToGeneration(
        receiverTree,
        senderData(latest),
        contentType,
        defaultKeyRetentionConfig,
        impl,
      )
      expect(received.key).toStrictEqual(latest.key)
      expect(received.nonce).toStrictEqual(latest.nonce)

      const serialized = encode(secretTreeEncoder, received.newTree)
      for (const secret of ratchetSecrets) {
        expect(received.consumed.some((value) => fastEqual(value, secret))).toBe(true)
        expect(serialized.some((_, i) => fastEqual(serialized.subarray(i, i + secret.length), secret))).toBe(false)
      }
      received.consumed.forEach(zeroOutUint8Array)
      expect(encode(secretTreeEncoder, received.newTree)).toStrictEqual(serialized)

      const restored = decode(secretTreeDecoder, serialized)
      if (restored === undefined) throw new Error("Could not restore secret tree")
      const skipped = restored.leafNodes[0]![ratchet].unusedGenerations
      expect(Object.keys(skipped)).toEqual(["0", "1"])
      const pendingDeletion: Uint8Array[] = []
      appendSecretTreeValues(restored, pendingDeletion)
      for (const cached of Object.values(skipped)) {
        expect(pendingDeletion).toContain(cached.key)
        expect(pendingDeletion).toContain(cached.nonce)
      }

      // Cached keys must work without any KDF access, including after serialization and zeroization.
      const noDerivation = {
        ...impl,
        kdf: { ...impl.kdf, expand: () => Promise.reject(new Error("Unexpected KDF call")) },
      }
      let tree = restored
      for (const generation of [1, 0]) {
        const message = messages[generation]!
        const baseNonce = skipped[generation]!.nonce.slice()
        const delayed = await ratchetToGeneration(
          tree,
          senderData(message),
          contentType,
          defaultKeyRetentionConfig,
          noDerivation,
        )
        expect(delayed.key).toStrictEqual(message.key)
        expect(delayed.nonce).toStrictEqual(message.nonce)
        expect(skipped[generation]!.nonce).toStrictEqual(baseNonce)
        tree = delayed.newTree
        expect(tree.leafNodes[0]![ratchet].unusedGenerations[generation]).toBeUndefined()
        delayed.consumed.forEach(zeroOutUint8Array)
        await expect(
          ratchetToGeneration(tree, senderData(message), contentType, defaultKeyRetentionConfig, noDerivation),
        ).rejects.toThrow("Desired gen in the past")
      }
    }
  },
)

test.each([0, 1])("evicts skipped keys and nonces when retaining %i generations", async (retainKeysForGenerations) => {
  const { cs, receiverTree, messages } = await setup(SUITE, contentTypes.application)
  const config = { ...defaultKeyRetentionConfig, retainKeysForGenerations }
  const result = await ratchetToGeneration(receiverTree, senderData(messages[2]!), contentTypes.application, config, cs)
  expect(Object.keys(result.newTree.leafNodes[0]!.application.unusedGenerations)).toEqual(
    retainKeysForGenerations === 0 ? [] : ["1"],
  )
  for (let generation = 0; generation < 2 - retainKeysForGenerations; generation++) {
    const message = messages[generation]!
    const baseNonce = message.nonce.slice()
    for (let i = 0; i < 4; i++) baseNonce[i]! ^= message.reuseGuard[i]!
    expect(result.consumed.some((value) => fastEqual(value, message.key))).toBe(true)
    expect(result.consumed.some((value) => fastEqual(value, baseNonce))).toBe(true)
  }
})
