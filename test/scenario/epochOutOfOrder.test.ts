import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { createApplicationMessage, createProposal } from "../../src/createMessage.js"
import { processMessage, processPrivateMessage } from "../../src/processMessages.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { shuffledIndices, testEveryoneCanMessageEveryone } from "./common.js"

import { defaultKeyRetentionConfig } from "../../src/keyRetentionConfig.js"
import { ClientState } from "../../src/clientState.js"
import { CiphersuiteImpl } from "../../src/crypto/ciphersuite.js"
import { KeyRetentionConfig } from "../../src/keyRetentionConfig.js"
import { ValidationError } from "../../src/mlsError.js"
import { defaultClientConfig, type ClientConfig } from "../../src/clientConfig.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { MlsFramedMessage } from "../../src/message.js"

describe("Out of order message processing by epoch", () => {
  test.concurrent.each(Object.keys(ciphersuites))(`Out of order epoch %s`, async (cs) => {
    await epochOutOfOrder(cs as CiphersuiteName)
  })

  test.concurrent.each(Object.keys(ciphersuites))(`Out of order epoch random %s`, async (cs) => {
    await epochOutOfOrderRandom(cs as CiphersuiteName, defaultKeyRetentionConfig.retainKeysForEpochs)
  })

  test.concurrent.each(Object.keys(ciphersuites))(`Out of order epoch limit reached fails %s`, async (cs) => {
    await epochOutOfOrderLimitFails(cs as CiphersuiteName, 3)
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
    keyRetentionConfig: retainConfig ?? defaultKeyRetentionConfig,
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

  // group starts at epoch 0
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

  // alice adds bob and initiates epoch 1
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

  // bob joins at epoch 1
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

async function epochOutOfOrder(cipherSuite: CiphersuiteName) {
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

  // alice sends the first message in epoch 1
  const aliceCreateFirstMessageResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    state: aliceGroup,
    message: firstMessage,
  })
  aliceGroup = aliceCreateFirstMessageResult.newState

  // alice sends a proposal message in epoch 1
  const aliceCreateFirstProposalResult = await createProposal({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    state: aliceGroup,
    wireAsPublicMessage: false,
    proposal: { proposalType: 1000, proposalData: new Uint8Array() },
  })
  aliceGroup = aliceCreateFirstProposalResult.newState

  // bob creates an empty commit and goes to epoch 2
  const emptyCommitResult1 = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: bobGroup,
  })
  bobGroup = emptyCommitResult1.newState

  if (emptyCommitResult1.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  // alice processes the empty commit and goes to epoch 2
  const aliceProcessFirstCommitResult = await processPrivateMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: aliceGroup,
    privateMessage: emptyCommitResult1.commit.privateMessage,
  })
  aliceGroup = aliceProcessFirstCommitResult.newState

  // alice sends the 2nd message in epoch 2
  const aliceCreateSecondMessageResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    state: aliceGroup,
    message: secondMessage,
  })
  aliceGroup = aliceCreateSecondMessageResult.newState

  // bob creates an empty commit and goes to epoch 3
  const emptyCommitResult2 = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: bobGroup,
  })
  bobGroup = emptyCommitResult2.newState

  if (emptyCommitResult2.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  // alice processes the empty commit and goes to epoch 3
  const aliceProcessSecondCommitResult = await processPrivateMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: aliceGroup,
    privateMessage: emptyCommitResult2.commit.privateMessage,
  })
  aliceGroup = aliceProcessSecondCommitResult.newState

  // alice sends the 3rd message in epoch 3
  const aliceCreateThirdMessageResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    state: aliceGroup,
    message: thirdMessage,
  })
  aliceGroup = aliceCreateThirdMessageResult.newState

  // bob creates an empty commit and goes to epoch 4
  const emptyCommitResult3 = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: bobGroup,
  })
  bobGroup = emptyCommitResult3.newState

  if (emptyCommitResult3.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  // alice processes the empty commit and goes to epoch 4
  const aliceProcessThirdCommitResult = await processPrivateMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      clientConfig,
    },
    state: aliceGroup,
    privateMessage: emptyCommitResult3.commit.privateMessage,
  })
  aliceGroup = aliceProcessThirdCommitResult.newState

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

  //bob won't be able to receive the proposal from an older epoch

  if (aliceCreateFirstProposalResult.message.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  await expect(
    processMessage({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        clientConfig,
      },
      state: bobGroup,
      message: aliceCreateFirstProposalResult.message,
    }),
  ).rejects.toThrow(ValidationError)

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}

async function epochOutOfOrderRandom(cipherSuite: CiphersuiteName, totalMessages: number) {
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
    // alice sends the first message in current epoch
    aliceGroup = createMessageResult.newState

    // bob creates an empty commit and goes to next epoch
    const emptyCommitResult = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        clientConfig,
      },
      state: bobGroup,
    })
    bobGroup = emptyCommitResult.newState

    if (emptyCommitResult.commit.wireformat !== wireformats.mls_private_message)
      throw new Error("Expected private message")

    // alice processes the empty commit and goes to next epoch
    const aliceProcessCommitResult = await processPrivateMessage({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        clientConfig,
      },
      state: aliceGroup,
      privateMessage: emptyCommitResult.commit.privateMessage,
    })
    aliceGroup = aliceProcessCommitResult.newState
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

async function epochOutOfOrderLimitFails(cipherSuite: CiphersuiteName, totalMessages: number) {
  const retainConfig = { ...defaultKeyRetentionConfig, retainKeysForEpochs: totalMessages - 1 }
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
  for (let i = 0; i < totalMessages; i++) {
    const createMessageResult = await createApplicationMessage({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
      state: aliceGroup,
      message,
    })
    // alice sends the first message in current epoch
    aliceGroup = createMessageResult.newState

    // bob creates an empty commit and goes to next epoch
    const emptyCommitResult = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        clientConfig,
      },
      state: bobGroup,
    })
    bobGroup = emptyCommitResult.newState

    if (emptyCommitResult.commit.wireformat !== wireformats.mls_private_message)
      throw new Error("Expected private message")

    // alice processes the empty commit and goes to next epoch
    const aliceProcessCommitResult = await processPrivateMessage({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        clientConfig,
      },
      state: aliceGroup,
      privateMessage: emptyCommitResult.commit.privateMessage,
    })
    aliceGroup = aliceProcessCommitResult.newState
    messages.push(createMessageResult.message)
  }

  //process last message
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
