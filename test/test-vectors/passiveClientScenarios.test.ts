import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { KeyPackage, PrivateKeyPackage } from "../../src/keyPackage"
import { hexToBytes } from "@noble/ciphers/utils"
import jsonCommit from "../../test_vectors/passive-client-handling-commit.json"
import jsonRandom from "../../test_vectors/passive-client-random.json"
import jsonWelcome from "../../test_vectors/passive-client-welcome.json"
import { hpkeKeysMatch, signatureKeysMatch } from "../crypto/keyMatch"
import { decodeMlsMessage } from "../../src/message"
import { decodeRatchetTree } from "../../src/ratchetTree"

import { joinGroup, processPrivateMessage, processPublicMessage } from "../../src/clientState"
import { bytesToBase64 } from "../../src/util/byteArray"

for (const [index, x] of jsonCommit.entries()) {
  test(`passive-client-handling-commit test vectors ${index}`, async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testPassiveClientScenario(x, impl)
  })
}

for (const [index, x] of jsonRandom.entries()) {
  test(`passive-client-random test vectors ${index}`, async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testPassiveClientScenario(x, impl)
  }, 20000)
}

for (const [index, x] of jsonWelcome.entries()) {
  test(`passive-client-welcome test vectors ${index}`, async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testPassiveClientScenario(x, impl)
  })
}

async function testPassiveClientScenario(data: MlsGroupState, impl: CiphersuiteImpl) {
  const kp = decodeMlsMessage(hexToBytes(data.key_package), 0)

  if (kp === undefined || kp[0].wireformat !== "mls_key_package") throw new Error("Could not decode KeyPackage")
  await verifyKeys(data, kp[0].keyPackage, impl)

  const welcome = decodeMlsMessage(hexToBytes(data.welcome), 0)

  if (welcome === undefined || welcome[0].wireformat !== "mls_welcome") throw new Error("Could not decode Welcome")

  const pks: PrivateKeyPackage = {
    hpkePrivateKey: hexToBytes(data.encryption_priv),
    initPrivateKey: hexToBytes(data.init_priv),
    signaturePrivateKey: hexToBytes(data.signature_priv),
  }

  const tree = data.ratchet_tree !== null ? decodeRatchetTree(hexToBytes(data.ratchet_tree), 0)?.[0] : undefined
  let state = await joinGroup(
    welcome[0].welcome,
    kp[0].keyPackage,
    pks,
    data.external_psks.map((ep) => [hexToBytes(ep.psk_id), hexToBytes(ep.psk)] as const),
    impl,
    tree,
  )

  expect(state.keySchedule.epochAuthenticator).toStrictEqual(hexToBytes(data.initial_epoch_authenticator))

  const psks: Record<string, Uint8Array> = data.external_psks.reduce(
    (acc, psk) => ({ ...acc, [bytesToBase64(hexToBytes(psk.psk_id))]: hexToBytes(psk.psk) }),
    {},
  )

  for (const epoch of data.epochs) {
    for (const proposal of epoch.proposals) {
      const mlsProposal = decodeMlsMessage(hexToBytes(proposal), 0)
      if (
        mlsProposal === undefined ||
        (mlsProposal[0].wireformat !== "mls_private_message" && mlsProposal[0].wireformat !== "mls_public_message")
      )
        throw new Error("Could not decode proposal message")

      if (mlsProposal[0].wireformat === "mls_private_message") {
        const res = await processPrivateMessage(state, mlsProposal[0].privateMessage, psks, impl)
        if (res.kind !== "applicationMessage") {
          state = res.newState
        }
      } else {
        state = await processPublicMessage(state, mlsProposal[0].publicMessage, psks, impl)
      }
    }

    const mlsCommit = decodeMlsMessage(hexToBytes(epoch.commit), 0)
    if (
      mlsCommit === undefined ||
      (mlsCommit[0].wireformat !== "mls_private_message" && mlsCommit[0].wireformat !== "mls_public_message")
    )
      throw new Error("Could not decode commit message")

    if (mlsCommit[0].wireformat === "mls_private_message") {
      const res = await processPrivateMessage(state, mlsCommit[0].privateMessage, psks, impl)
      if (res.kind !== "applicationMessage") {
        state = res.newState
      }
    } else {
      state = await processPublicMessage(state, mlsCommit[0].publicMessage, psks, impl)
    }

    expect(state.keySchedule.epochAuthenticator).toStrictEqual(hexToBytes(epoch.epoch_authenticator))
  }
}

async function verifyKeys(data: MlsGroupState, kp: KeyPackage, impl: CiphersuiteImpl) {
  const hpke = await hpkeKeysMatch(kp.leafNode.hpkePublicKey, hexToBytes(data.encryption_priv), impl.hpke)
  expect(hpke).toBe(true)

  const hpkeInit = await hpkeKeysMatch(kp.initKey, hexToBytes(data.init_priv), impl.hpke)
  expect(hpkeInit).toBe(true)

  const sig = signatureKeysMatch(kp.leafNode.signaturePublicKey, hexToBytes(data.signature_priv), impl.signature)
  expect(sig).toBe(true)
  hexToBytes(data.init_priv)
}

type MlsGroupState = {
  cipher_suite: number
  external_psks: ExternalPsk[]
  key_package: string
  signature_priv: string
  encryption_priv: string
  init_priv: string
  welcome: string
  ratchet_tree: string | null
  initial_epoch_authenticator: string
  epochs: Epoch[]
}

type ExternalPsk = {
  psk_id: string
  psk: string
}

type Epoch = {
  proposals: string[]
  commit: string
  epoch_authenticator: string
}
