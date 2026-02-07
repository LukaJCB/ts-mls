import { ClientState, createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { createApplicationMessage } from "../../src/createMessage.js"
import { processMessage } from "../../src/processMessages.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteImpl, CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { shuffledIndices, testEveryoneCanMessageEveryone } from "./common.js"

import { defaultKeyRetentionConfig, KeyRetentionConfig } from "../../src/keyRetentionConfig.js"
import { ValidationError } from "../../src/mlsError.js"
import { defaultClientConfig, type ClientConfig } from "../../src/clientConfig.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { MlsFramedMessage } from "../../src/message.js"

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
  clientConfig: ClientConfig
}

async function setupTestParticipants(
  cipherSuite: CiphersuiteName,
  retainConfig?: KeyRetentionConfig,
): Promise<TestParticipants> {
  const impl = await getCiphersuiteImpl(cipherSuite)
  const clientConfig: ClientConfig = {
    ...defaultClientConfig,
    keyRetentionConfig: retainConfig ?? defaultClientConfig.keyRetentionConfig,
  }

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({
    credential: aliceCredential,
    cipherSuite: impl,
  })

  const groupId = new TextEncoder().encode("group1")
  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({
    credential: bobCredential,
    cipherSuite: impl,
  })

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: aliceGroup,
    extraProposals: [addBobProposal],
    ratchetTreeExtension: true,
  })
  aliceGroup = addBobCommitResult.newState

  const bobGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    welcome: addBobCommitResult.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
  })

  return { aliceGroup, bobGroup, impl, clientConfig }
}

async function generationOutOfOrder(cipherSuite: CiphersuiteName) {
  const {
    aliceGroup: initialAliceGroup,
    bobGroup: initialBobGroup,
    impl,
    clientConfig,
  } = await setupTestParticipants(cipherSuite)

  let aliceGroup = initialAliceGroup
  let bobGroup = initialBobGroup

  const firstMessage = new TextEncoder().encode("Hello bob!")
  const secondMessage = new TextEncoder().encode("How are ya?")
  const thirdMessage = new TextEncoder().encode("Have you heard the news?")

  // alice sends the first message
  const aliceCreateFirstMessageResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    state: aliceGroup,
    message: firstMessage,
  })
  aliceGroup = aliceCreateFirstMessageResult.newState

  const aliceCreateSecondMessageResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    state: aliceGroup,
    message: secondMessage,
  })
  aliceGroup = aliceCreateSecondMessageResult.newState

  const aliceCreateThirdMessageResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    state: aliceGroup,
    message: thirdMessage,
  })
  aliceGroup = aliceCreateThirdMessageResult.newState

  // bob receives 3rd message first
  const bobProcessThirdMessageResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: bobGroup,
    message: aliceCreateThirdMessageResult.message,
  })
  bobGroup = bobProcessThirdMessageResult.newState

  // then bob receives the first message
  const bobProcessFirstMessageResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: bobGroup,
    message: aliceCreateFirstMessageResult.message,
  })
  bobGroup = bobProcessFirstMessageResult.newState

  // bob receives 2nd message last
  const bobProcessSecondMessageResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: bobGroup,
    message: aliceCreateSecondMessageResult.message,
  })
  bobGroup = bobProcessSecondMessageResult.newState

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}

async function generationOutOfOrderRandom(cipherSuite: CiphersuiteName, totalMessages: number) {
  const {
    aliceGroup: initialAliceGroup,
    bobGroup: initialBobGroup,
    impl,
    clientConfig,
  } = await setupTestParticipants(cipherSuite)

  let aliceGroup = initialAliceGroup
  let bobGroup = initialBobGroup

  const message = new TextEncoder().encode("Hi!")

  const messages: MlsFramedMessage[] = []
  for (let i = 0; i < totalMessages; i++) {
    const createMessageResult = await createApplicationMessage({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
      state: aliceGroup,
      message,
    })
    aliceGroup = createMessageResult.newState
    messages.push(createMessageResult.message)
  }

  const shuffledMessages = shuffledIndices(messages).map((i) => messages[i]!)

  for (const msg of shuffledMessages) {
    const bobProcessMessageResult = await processMessage({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        clientConfig,
      },
      state: bobGroup,
      message: msg,
    })
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
    clientConfig,
  } = await setupTestParticipants(cipherSuite, retainConfig)

  let aliceGroup = initialAliceGroup
  let bobGroup = initialBobGroup

  const message = new TextEncoder().encode("Hi!")

  const messages: MlsFramedMessage[] = []
  for (let i = 0; i < totalMessages + 1; i++) {
    const createMessageResult = await createApplicationMessage({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
      state: aliceGroup,
      message,
    })
    aliceGroup = createMessageResult.newState
    messages.push(createMessageResult.message)
  }

  // read the last message first
  const processResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: bobGroup,
    message: messages.at(-1)!,
  })
  bobGroup = processResult.newState

  // should fail reading the first message
  await expect(
    processMessage({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        clientConfig,
      },
      state: bobGroup,
      message: messages.at(0)!,
    }),
  ).rejects.toThrow(ValidationError)
}
