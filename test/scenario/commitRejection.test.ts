import {
  clientStateDecoder,
  clientStateEncoder,
  createApplicationMessage,
  createCommit,
  createGroup,
  defaultCredentialTypes,
  defaultKeyRetentionConfig,
  defaultProposalTypes,
  generateKeyPackage,
  generateSignatureKeyPair,
  getCiphersuiteImpl,
  joinGroup,
  processMessage,
  unsafeTestingAuthenticationService,
  wireformats,
  zeroOutUint8Array,
  type ClientState,
  type CreateCommitResult,
  type MlsContext,
} from "../../src/index.js"
import { defaultClientConfig } from "../../src/clientConfig.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { decryptSenderData } from "../../src/privateMessage.js"
import { fastEqual } from "../../src/util/byteArray.js"
import { processMessageEnsureNoMutation, testEveryoneCanMessageEveryone } from "./common.js"

interface Encryption {
  key: Uint8Array
  nonce: Uint8Array
  ciphertext: Uint8Array
}

function getSharedConsumed(result: CreateCommitResult): Uint8Array[] {
  return result.consumed.filter((secret) =>
    // eslint-disable-next-line no-object-comparison/array-includes-object -- Cleanup depends on shared buffer identity.
    result.consumedOnReject.includes(secret),
  )
}

async function setup(retainKeysForEpochs = 4) {
  const impl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
  const encryptions: Encryption[] = []
  const context: MlsContext = {
    cipherSuite: {
      ...impl,
      hpke: {
        ...impl.hpke,
        async encryptAead(key, nonce, aad, plaintext) {
          const ciphertext = await impl.hpke.encryptAead(key, nonce, aad, plaintext)
          encryptions.push({ key: key.slice(), nonce: nonce.slice(), ciphertext: ciphertext.slice() })
          return ciphertext
        },
      },
    },
    authService: unsafeTestingAuthenticationService,
    clientConfig: {
      ...defaultClientConfig,
      keyRetentionConfig: { ...defaultKeyRetentionConfig, retainKeysForEpochs },
    },
  }
  const makeMember = (identity: string) =>
    generateKeyPackage({
      cipherSuite: impl,
      credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode(identity) },
    })
  const alice = await makeMember("alice")
  const bob = await makeMember("bob")
  const initial = await createGroup({
    context,
    groupId: new TextEncoder().encode("commit-rejection"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })
  const added = await createCommit({
    context,
    state: initial,
    extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
  })
  const aliceGroup = added.newState
  added.consumed.forEach(zeroOutUint8Array)
  const bobGroup = await joinGroup({
    context,
    welcome: added.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })
  return { context, impl, aliceGroup, bobGroup, encryptions }
}

async function inspectCommit(
  result: CreateCommitResult,
  state: ClientState,
  context: MlsContext,
  encryptions: Encryption[],
) {
  if (result.commit.wireformat !== wireformats.mls_private_message) throw new Error("Expected private message")
  const message = result.commit.privateMessage
  const sender = await decryptSenderData(message, state.keySchedule.senderDataSecret, context.cipherSuite)
  if (sender === undefined) throw new Error("Expected sender data")
  const encryption = encryptions.find((e) => fastEqual(e.ciphertext, message.ciphertext))
  if (encryption === undefined) throw new Error("Expected recorded encryption")
  const baseNonce = encryption.nonce.slice()
  for (let i = 0; i < 4; i++) baseNonce[i]! ^= sender.reuseGuard[i]!
  return { generation: sender.generation, key: encryption.key, baseNonce }
}

test.each([false, true])("rejected commits advance the sending ratchet (initialized leaf: %s)", async (initialized) => {
  const { context, impl, aliceGroup, bobGroup, encryptions } = await setup()
  let state = aliceGroup
  if (initialized) {
    const application = await createApplicationMessage({ context, state, message: new Uint8Array([1]) })
    state = application.newState
    application.consumed.forEach(zeroOutUint8Array)
  }
  const previousState = encode(clientStateEncoder, state)
  const originalInitSecret = state.keySchedule.initSecret.slice()
  const rejected = await createCommit({ context, state })
  expect(encode(clientStateEncoder, state)).toStrictEqual(previousState)
  expect(rejected.newStateOnReject.groupContext.epoch).toBe(state.groupContext.epoch)
  expect(rejected.newState.groupContext.epoch).toBe(state.groupContext.epoch + 1n)
  const first = await inspectCommit(rejected, rejected.newStateOnReject, context, encryptions)
  state = rejected.newStateOnReject
  const sharedConsumed = getSharedConsumed(rejected)
  expect(sharedConsumed.length).toBeGreaterThan(0)
  sharedConsumed.forEach(zeroOutUint8Array)
  rejected.consumedOnReject.forEach(zeroOutUint8Array)
  expect(state.keySchedule.initSecret).toStrictEqual(originalInitSecret)

  // Persisting and restoring the current state must preserve the advanced sending generation.
  state = clientStateDecoder(encode(clientStateEncoder, state), 0)![0]
  const retried = await createCommit({ context, state })
  const second = await inspectCommit(retried, retried.newStateOnReject, context, encryptions)
  expect([first.generation, second.generation]).toStrictEqual([0, 1])
  expect(second.key).not.toStrictEqual(first.key)
  expect(second.baseNonce).not.toStrictEqual(first.baseNonce)
  getSharedConsumed(retried).forEach(zeroOutUint8Array)

  const bobAfterCommit = await processMessageEnsureNoMutation({ context, state: bobGroup, message: retried.commit })
  state = retried.newState
  retried.consumed.forEach(zeroOutUint8Array)
  bobAfterCommit.consumed.forEach(zeroOutUint8Array)
  expect(state.keySchedule.epochAuthenticator).toStrictEqual(bobAfterCommit.newState.keySchedule.epochAuthenticator)
  await testEveryoneCanMessageEveryone([state, bobAfterCommit.newState], impl)
})

test.each([0, 4])("handles a competing commit after rejection with %i retained epochs", async (retainedEpochs) => {
  const { context, impl, aliceGroup, bobGroup } = await setup(retainedEpochs)
  const candidate = await createCommit({ context, state: aliceGroup })
  const currentState = candidate.newStateOnReject
  candidate.consumedOnReject.forEach(zeroOutUint8Array)

  const winner = await createCommit({ context, state: bobGroup })
  const accepted = await processMessageEnsureNoMutation({ context, state: currentState, message: winner.commit })
  accepted.consumed.forEach(zeroOutUint8Array)
  winner.consumed.forEach(zeroOutUint8Array)
  expect(accepted.newState.keySchedule.epochAuthenticator).toStrictEqual(winner.newState.keySchedule.epochAuthenticator)
  await testEveryoneCanMessageEveryone([accepted.newState, winner.newState], impl)
})

test("rejection preserves history that merging would prune", async () => {
  const { context, impl, aliceGroup, bobGroup } = await setup(1)
  const firstEpoch = aliceGroup.groupContext.epoch
  const plaintext = new TextEncoder().encode("Delayed message before the candidate")
  const delayed = await createApplicationMessage({ context, state: bobGroup, message: plaintext })
  const accepted = await createCommit({ context, state: aliceGroup })
  let state = accepted.newState
  accepted.consumed.forEach(zeroOutUint8Array)
  const rejected = await createCommit({ context, state })
  expect(rejected.newState.historicalReceiverData.has(firstEpoch)).toBe(false)
  state = rejected.newStateOnReject
  rejected.consumedOnReject.forEach(zeroOutUint8Array)

  const received = await processMessageEnsureNoMutation({ context, state, message: delayed.message })
  if (received.kind !== "applicationMessage") throw new Error("Expected application message")
  expect(received.message).toStrictEqual(plaintext)
  received.consumed.forEach(zeroOutUint8Array)
  const bobAfterCommit = await processMessageEnsureNoMutation({
    context,
    state: delayed.newState,
    message: accepted.commit,
  })
  bobAfterCommit.consumed.forEach(zeroOutUint8Array)
  await testEveryoneCanMessageEveryone([received.newState, bobAfterCommit.newState], impl)
})

test("rejecting an Add-only commit preserves private keys shared with the current epoch", async () => {
  const { context, impl, aliceGroup, bobGroup } = await setup()
  const charlie = await generateKeyPackage({
    cipherSuite: impl,
    credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode("charlie") },
  })
  const previousPrivatePath = structuredClone(aliceGroup.privatePath)
  const rejected = await createCommit({
    context,
    state: aliceGroup,
    extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: charlie.publicPackage } }],
  })
  expect(rejected.welcome).toBeDefined()
  expect(rejected.newState.privatePath.privateKeys[0]).toBe(rejected.newStateOnReject.privatePath.privateKeys[0])
  const currentState = rejected.newStateOnReject
  rejected.consumedOnReject.forEach(zeroOutUint8Array)
  expect(currentState.privatePath).toStrictEqual(previousPrivatePath)

  const retried = await createCommit({ context, state: currentState })
  const processed = await processMessage({ context, state: bobGroup, message: retried.commit })
  retried.consumed.forEach(zeroOutUint8Array)
  processed.consumed.forEach(zeroOutUint8Array)
  await testEveryoneCanMessageEveryone([retried.newState, processed.newState], impl)
})

test.each([false, true])(
  "rejection erases candidate secrets while preserving current keys (public: %s)",
  async (publicMessage) => {
    const { context, impl, aliceGroup, bobGroup } = await setup()
    const signingKeys = await generateSignatureKeyPair(impl)
    const originalCurrentKeys = structuredClone({
      keySchedule: aliceGroup.keySchedule,
      privatePath: aliceGroup.privatePath,
      signaturePrivateKey: aliceGroup.signaturePrivateKey,
    })
    const signingKeyBefore = signingKeys.signKey.slice()
    const rejected = await createCommit({
      context,
      state: aliceGroup,
      wireAsPublicMessage: publicMessage,
      leafNodePatch: { signatureKeyPair: signingKeys },
    })
    const currentState = rejected.newStateOnReject
    rejected.consumedOnReject.forEach(zeroOutUint8Array)
    expect({
      keySchedule: currentState.keySchedule,
      privatePath: currentState.privatePath,
      signaturePrivateKey: currentState.signaturePrivateKey,
    }).toStrictEqual(originalCurrentKeys)
    expect(signingKeys.signKey).toStrictEqual(signingKeyBefore)
    for (const secret of Object.values({ ...rejected.newState.keySchedule })) {
      expect(secret.every((byte) => byte === 0)).toBe(true)
    }
    for (const secret of Object.values(rejected.newState.secretTree.intermediateNodes)) {
      expect(secret.every((byte) => byte === 0)).toBe(true)
    }
    for (const [node, secret] of Object.entries(rejected.newState.privatePath.privateKeys)) {
      if (secret !== currentState.privatePath.privateKeys[Number(node)]) {
        expect(secret.every((byte) => byte === 0)).toBe(true)
      }
    }

    // Continuing after rejection must use the unchanged signing identity and valid current-epoch secrets.
    const retried = await createCommit({ context, state: currentState })
    const processed = await processMessage({ context, state: bobGroup, message: retried.commit })
    retried.consumed.forEach(zeroOutUint8Array)
    processed.consumed.forEach(zeroOutUint8Array)
    await testEveryoneCanMessageEveryone([retried.newState, processed.newState], impl)
  },
)
