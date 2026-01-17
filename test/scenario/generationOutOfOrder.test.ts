import { ClientState, createGroup, joinGroup, makePskIndex } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { createApplicationMessage } from "../../src/createMessage.js"
import { processPrivateMessage } from "../../src/processMessages.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteImpl, CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { shuffledIndices, testEveryoneCanMessageEveryone } from "./common.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { PrivateMessage } from "../../src/privateMessage.js"
import { defaultKeyRetentionConfig, KeyRetentionConfig } from "../../src/keyRetentionConfig.js"
import { ValidationError } from "../../src/mlsError.js"
import { defaultClientConfig } from "../../src/clientConfig.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

describe("Out of order message processing by generation", () => {
  test.concurrent.each(Object.keys(ciphersuites))(`Out of order generation %s`, async (cs) => {
    await generationOutOfOrder(cs as CiphersuiteName)
  })

  test.concurrent.each(Object.keys(ciphersuites))(`Out of order generation random %s`, async (cs) => {
    await generationOutOfOrderRandom(cs as CiphersuiteName, defaultKeyRetentionConfig.retainKeysForGenerations)
  })

  test.concurrent.each(Object.keys(ciphersuites))(`Out of order generation limit reached fails %s`, async (cs) => {
    await generationOutOfOrderLimitFails(cs as CiphersuiteName, 10)
  })
})

type TestParticipants = {
  aliceGroup: ClientState
  bobGroup: ClientState
  impl: CiphersuiteImpl
}

async function setupTestParticipants(
  cipherSuite: CiphersuiteName,
  retainConfig?: KeyRetentionConfig,
): Promise<TestParticipants> {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")
  let aliceGroup = await createGroup(
    groupId,
    alice.publicPackage,
    alice.privatePackage,
    [],
    unsafeTestingAuthenticationService,
    impl,
  )

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    {
      extraProposals: [addBobProposal],
      ratchetTreeExtension: true,
    },
  )
  aliceGroup = addBobCommitResult.newState

  const bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    unsafeTestingAuthenticationService,
    impl,
    undefined,
    undefined,
    { ...defaultClientConfig, keyRetentionConfig: retainConfig ?? defaultClientConfig.keyRetentionConfig },
  )

  return { aliceGroup, bobGroup, impl }
}

async function generationOutOfOrder(cipherSuite: CiphersuiteName) {
  const { aliceGroup: initialAliceGroup, bobGroup: initialBobGroup, impl } = await setupTestParticipants(cipherSuite)

  let aliceGroup = initialAliceGroup
  let bobGroup = initialBobGroup

  const firstMessage = new TextEncoder().encode("Hello bob!")
  const secondMessage = new TextEncoder().encode("How are ya?")
  const thirdMessage = new TextEncoder().encode("Have you heard the news?")

  // alice sends the first message
  const aliceCreateFirstMessageResult = await createApplicationMessage(aliceGroup, firstMessage, impl)
  aliceGroup = aliceCreateFirstMessageResult.newState

  const aliceCreateSecondMessageResult = await createApplicationMessage(aliceGroup, secondMessage, impl)
  aliceGroup = aliceCreateSecondMessageResult.newState

  const aliceCreateThirdMessageResult = await createApplicationMessage(aliceGroup, thirdMessage, impl)
  aliceGroup = aliceCreateThirdMessageResult.newState

  // bob receives 3rd message first
  const bobProcessThirdMessageResult = await processPrivateMessage(
    bobGroup,
    aliceCreateThirdMessageResult.privateMessage,
    makePskIndex(bobGroup, {}),
    unsafeTestingAuthenticationService,
    impl,
  )
  bobGroup = bobProcessThirdMessageResult.newState

  // then bob receives the first message
  const bobProcessFirstMessageResult = await processPrivateMessage(
    bobGroup,
    aliceCreateFirstMessageResult.privateMessage,
    makePskIndex(bobGroup, {}),
    unsafeTestingAuthenticationService,
    impl,
  )
  bobGroup = bobProcessFirstMessageResult.newState

  // bob receives 2nd message last
  const bobProcessSecondMessageResult = await processPrivateMessage(
    bobGroup,
    aliceCreateSecondMessageResult.privateMessage,
    makePskIndex(bobGroup, {}),
    unsafeTestingAuthenticationService,
    impl,
  )
  bobGroup = bobProcessSecondMessageResult.newState

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}

async function generationOutOfOrderRandom(cipherSuite: CiphersuiteName, totalMessages: number) {
  const { aliceGroup: initialAliceGroup, bobGroup: initialBobGroup, impl } = await setupTestParticipants(cipherSuite)

  let aliceGroup = initialAliceGroup
  let bobGroup = initialBobGroup

  const message = new TextEncoder().encode("Hi!")

  const messages: PrivateMessage[] = []
  for (let i = 0; i < totalMessages; i++) {
    const createMessageResult = await createApplicationMessage(aliceGroup, message, impl)
    aliceGroup = createMessageResult.newState
    messages.push(createMessageResult.privateMessage)
  }

  const shuffledMessages = shuffledIndices(messages).map((i) => messages[i]!)

  for (const msg of shuffledMessages) {
    const bobProcessMessageResult = await processPrivateMessage(
      bobGroup,
      msg,
      makePskIndex(bobGroup, {}),
      unsafeTestingAuthenticationService,
      impl,
    )
    bobGroup = bobProcessMessageResult.newState
  }

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}

async function generationOutOfOrderLimitFails(cipherSuite: CiphersuiteName, totalMessages: number) {
  const retainConfig = { ...defaultKeyRetentionConfig, retainKeysForGenerations: totalMessages - 1 }
  const {
    aliceGroup: initialAliceGroup,
    bobGroup: initialBobGroup,
    impl,
  } = await setupTestParticipants(cipherSuite, retainConfig)

  let aliceGroup = initialAliceGroup
  let bobGroup = initialBobGroup

  const message = new TextEncoder().encode("Hi!")

  const messages: PrivateMessage[] = []
  for (let i = 0; i < totalMessages + 1; i++) {
    const createMessageResult = await createApplicationMessage(aliceGroup, message, impl)
    aliceGroup = createMessageResult.newState
    messages.push(createMessageResult.privateMessage)
  }

  // read the last message first
  const processResult = await processPrivateMessage(
    bobGroup,
    messages.at(-1)!,
    emptyPskIndex,
    unsafeTestingAuthenticationService,
    impl,
  )
  bobGroup = processResult.newState

  // should fail reading the first message
  await expect(
    processPrivateMessage(bobGroup, messages.at(0)!, emptyPskIndex, unsafeTestingAuthenticationService, impl),
  ).rejects.toThrow(ValidationError)
}
