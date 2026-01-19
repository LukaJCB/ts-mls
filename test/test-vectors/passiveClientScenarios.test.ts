import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { KeyPackage, PrivateKeyPackage } from "../../src/keyPackage.js"
import { hexToBytes } from "@noble/ciphers/utils.js"
import jsonCommit from "../../test_vectors/passive-client-handling-commit.json"
import jsonRandom from "../../test_vectors/passive-client-random.json"
import jsonWelcome from "../../test_vectors/passive-client-welcome.json"
import { hpkeKeysMatch, signatureKeysMatch } from "../crypto/keyMatch.js"
import { mlsMessageDecoder } from "../../src/message.js"
import { ratchetTreeDecoder } from "../../src/ratchetTree.js"

import { joinGroup } from "../../src/clientState.js"
import { processPrivateMessage, processPublicMessage } from "../../src/processMessages.js"
import { bytesToBase64 } from "../../src/util/byteArray.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(jsonCommit.map((x, index) => [index, x]))(
  `passive-client-handling-commit test vectors %i`,
  async (_index, x) => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testPassiveClientScenario(x, impl)
  },
)

test.concurrent.each(jsonRandom.map((x, index) => [index, x]))(
  `passive-client-random test vectors %i`,
  async (_index, x) => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testPassiveClientScenario(x, impl)
  },
  60000,
)

test.concurrent.each(jsonWelcome.map((x, index) => [index, x]))(
  `passive-client-welcome test vectors %i`,
  async (_index, x) => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testPassiveClientScenario(x, impl)
  },
)

async function testPassiveClientScenario(data: MlsGroupState, impl: CiphersuiteImpl) {
  const kp = mlsMessageDecoder(hexToBytes(data.key_package), 0)

  if (kp === undefined || kp[0].wireformat !== wireformats.mls_key_package)
    throw new Error("Could not decode KeyPackage")
  await verifyKeys(data, kp[0].keyPackage, impl)

  const welcome = mlsMessageDecoder(hexToBytes(data.welcome), 0)

  if (welcome === undefined || welcome[0].wireformat !== wireformats.mls_welcome)
    throw new Error("Could not decode Welcome")

  const pks: PrivateKeyPackage = {
    hpkePrivateKey: hexToBytes(data.encryption_priv),
    initPrivateKey: hexToBytes(data.init_priv),
    signaturePrivateKey: hexToBytes(data.signature_priv),
  }

  const tree = data.ratchet_tree !== null ? ratchetTreeDecoder(hexToBytes(data.ratchet_tree), 0)?.[0] : undefined

  const psks: Record<string, Uint8Array> = data.external_psks.reduce(
    (acc, psk) => ({ ...acc, [bytesToBase64(hexToBytes(psk.psk_id))]: hexToBytes(psk.psk) }),
    {},
  )
  let state = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      externalPsks: psks,
    },
    welcome: welcome[0].welcome,
    keyPackage: kp[0].keyPackage,
    privateKeys: pks,
    ratchetTree: tree,
  })

  expect(state.keySchedule.epochAuthenticator).toStrictEqual(hexToBytes(data.initial_epoch_authenticator))

  for (const epoch of data.epochs) {
    for (const proposal of epoch.proposals) {
      const mlsProposal = mlsMessageDecoder(hexToBytes(proposal), 0)
      if (
        mlsProposal === undefined ||
        (mlsProposal[0].wireformat !== wireformats.mls_private_message &&
          mlsProposal[0].wireformat !== wireformats.mls_public_message)
      )
        throw new Error("Could not decode proposal message")

      if (mlsProposal[0].wireformat === wireformats.mls_private_message) {
        const res = await processPrivateMessage({
          context: {
            cipherSuite: impl,
            authService: unsafeTestingAuthenticationService,
            externalPsks: psks,
          },
          state,
          privateMessage: mlsProposal[0].privateMessage,
        })

        state = res.newState
      } else {
        const res = await processPublicMessage({
          context: {
            cipherSuite: impl,
            authService: unsafeTestingAuthenticationService,
            externalPsks: psks,
          },
          state,
          publicMessage: mlsProposal[0].publicMessage,
        })

        state = res.newState
      }
    }

    const mlsCommit = mlsMessageDecoder(hexToBytes(epoch.commit), 0)
    if (
      mlsCommit === undefined ||
      (mlsCommit[0].wireformat !== wireformats.mls_private_message &&
        mlsCommit[0].wireformat !== wireformats.mls_public_message)
    )
      throw new Error("Could not decode commit message")

    if (mlsCommit[0].wireformat === wireformats.mls_private_message) {
      const res = await processPrivateMessage({
        context: {
          cipherSuite: impl,
          authService: unsafeTestingAuthenticationService,
          externalPsks: psks,
        },
        state,
        privateMessage: mlsCommit[0].privateMessage,
      })

      state = res.newState
    } else {
      const res = await processPublicMessage({
        context: {
          cipherSuite: impl,
          authService: unsafeTestingAuthenticationService,
          externalPsks: psks,
        },
        state,
        publicMessage: mlsCommit[0].publicMessage,
      })
      state = res.newState
    }

    expect(state.keySchedule.epochAuthenticator).toStrictEqual(hexToBytes(epoch.epoch_authenticator))
  }
}

async function verifyKeys(data: MlsGroupState, kp: KeyPackage, impl: CiphersuiteImpl) {
  const hpke = await hpkeKeysMatch(kp.leafNode.hpkePublicKey, hexToBytes(data.encryption_priv), impl.hpke)
  expect(hpke).toBe(true)

  const hpkeInit = await hpkeKeysMatch(kp.initKey, hexToBytes(data.init_priv), impl.hpke)
  expect(hpkeInit).toBe(true)

  const sig = await signatureKeysMatch(kp.leafNode.signaturePublicKey, hexToBytes(data.signature_priv), impl.signature)
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
