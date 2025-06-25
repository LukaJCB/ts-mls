import { createGroup, joinGroup, makePskIndex } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { createApplicationMessage } from "../../src/createMessage"
import { processPrivateMessage } from "../../src/processMessages"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { ProposalAdd } from "../../src/proposal"
import { defaultCapabilities, defaultLifetime, shuffledIndices, testEveryoneCanMessageEveryone } from "./common"
import { PrivateMessage } from "../../src/privateMessage"
import { defaultKeyRetentionConfig } from "../../src/keyRetentionConfig"
import { ClientState } from "../../src/clientState"
import { CiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { KeyRetentionConfig } from "../../src/keyRetentionConfig"

describe("Out of order message processing by epoch", () => {
  for (const cs of Object.keys(ciphersuites)) {
    test(`Out of order epoch ${cs}`, async () => {
      await epochOutOfOrder(cs as CiphersuiteName)
    })
  }

  for (const cs of Object.keys(ciphersuites)) {
    test(`Out of order epoch random ${cs}`, async () => {
      await epochOutOfOrderRandom(cs as CiphersuiteName, defaultKeyRetentionConfig.retainKeysForEpochs)
    })
  }

  for (const cs of Object.keys(ciphersuites)) {
    test(`Out of order epoch limit reached fails ${cs}`, async () => {
      await epochOutOfOrderLimitFails(cs as CiphersuiteName, 3)
    })
  }
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

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  // group starts at epoch 0
  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  // alice adds bob and initiates epoch 1
  const addBobCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl, true)
  aliceGroup = addBobCommitResult.newState

  // bob joins at epoch 1
  const bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    undefined,
    undefined,
    retainConfig,
  )

  return { aliceGroup, bobGroup, impl }
}

async function epochOutOfOrder(cipherSuite: CiphersuiteName) {
  const { aliceGroup: initialAliceGroup, bobGroup: initialBobGroup, impl } = await setupTestParticipants(cipherSuite)

  let aliceGroup = initialAliceGroup
  let bobGroup = initialBobGroup

  const firstMessage = new TextEncoder().encode("Hello bob!")
  const secondMessage = new TextEncoder().encode("How are ya?")
  const thirdMessage = new TextEncoder().encode("Have you heard the news?")

  // alice sends the first message in epoch 1
  const aliceCreateFirstMessageResult = await createApplicationMessage(aliceGroup, firstMessage, impl)
  aliceGroup = aliceCreateFirstMessageResult.newState

  // bob creates an empty commit and goes to epoch 2
  const emptyCommitResult1 = await createCommit(bobGroup, emptyPskIndex, false, [], impl)
  bobGroup = emptyCommitResult1.newState

  if (emptyCommitResult1.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  // alice processes the empty commit and goes to epoch 2
  const aliceProcessFirstCommitResult = await processPrivateMessage(
    aliceGroup,
    emptyCommitResult1.commit.privateMessage,
    emptyPskIndex,
    impl,
  )
  aliceGroup = aliceProcessFirstCommitResult.newState

  // alice sends the 2nd message in epoch 2
  const aliceCreateSecondMessageResult = await createApplicationMessage(aliceGroup, secondMessage, impl)
  aliceGroup = aliceCreateSecondMessageResult.newState

  // bob creates an empty commit and goes to epoch 3
  const emptyCommitResult2 = await createCommit(bobGroup, emptyPskIndex, false, [], impl)
  bobGroup = emptyCommitResult2.newState

  if (emptyCommitResult2.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  // alice processes the empty commit and goes to epoch 3
  const aliceProcessSecondCommitResult = await processPrivateMessage(
    aliceGroup,
    emptyCommitResult2.commit.privateMessage,
    emptyPskIndex,
    impl,
  )
  aliceGroup = aliceProcessSecondCommitResult.newState

  // alice sends the 3rd message in epoch 3
  const aliceCreateThirdMessageResult = await createApplicationMessage(aliceGroup, thirdMessage, impl)
  aliceGroup = aliceCreateThirdMessageResult.newState

  // bob creates an empty commit and goes to epoch 4
  const emptyCommitResult3 = await createCommit(bobGroup, emptyPskIndex, false, [], impl)
  bobGroup = emptyCommitResult3.newState

  if (emptyCommitResult3.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  // alice processes the empty commit and goes to epoch 4
  const aliceProcessThirdCommitResult = await processPrivateMessage(
    aliceGroup,
    emptyCommitResult3.commit.privateMessage,
    emptyPskIndex,
    impl,
  )
  aliceGroup = aliceProcessThirdCommitResult.newState

  // bob receives 3rd message first
  const bobProcessThirdMessageResult = await processPrivateMessage(
    bobGroup,
    aliceCreateThirdMessageResult.privateMessage,
    makePskIndex(bobGroup, {}),
    impl,
  )
  bobGroup = bobProcessThirdMessageResult.newState

  // then bob receives the first message
  const bobProcessFirstMessageResult = await processPrivateMessage(
    bobGroup,
    aliceCreateFirstMessageResult.privateMessage,
    makePskIndex(bobGroup, {}),
    impl,
  )
  bobGroup = bobProcessFirstMessageResult.newState

  // bob receives 2nd message last
  const bobProcessSecondMessageResult = await processPrivateMessage(
    bobGroup,
    aliceCreateSecondMessageResult.privateMessage,
    makePskIndex(bobGroup, {}),
    impl,
  )
  bobGroup = bobProcessSecondMessageResult.newState

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}

async function epochOutOfOrderRandom(cipherSuite: CiphersuiteName, totalMessages: number) {
  const { aliceGroup: initialAliceGroup, bobGroup: initialBobGroup, impl } = await setupTestParticipants(cipherSuite)

  let aliceGroup = initialAliceGroup
  let bobGroup = initialBobGroup

  const message = new TextEncoder().encode("Hi!")

  let messages: PrivateMessage[] = []
  for (let i = 0; i < totalMessages; i++) {
    const createMessageResult = await createApplicationMessage(aliceGroup, message, impl)
    // alice sends the first message in current epoch
    aliceGroup = createMessageResult.newState

    // bob creates an empty commit and goes to next epoch
    const emptyCommitResult = await createCommit(bobGroup, emptyPskIndex, false, [], impl)
    bobGroup = emptyCommitResult.newState

    if (emptyCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

    // alice processes the empty commit and goes to next epoch
    const aliceProcessCommitResult = await processPrivateMessage(
      aliceGroup,
      emptyCommitResult.commit.privateMessage,
      emptyPskIndex,
      impl,
    )
    aliceGroup = aliceProcessCommitResult.newState
    messages.push(createMessageResult.privateMessage)
  }

  const shuffledMessages = shuffledIndices(messages).map((i) => messages[i]!)

  for (const msg of shuffledMessages) {
    const bobProcessMessageResult = await processPrivateMessage(bobGroup, msg, makePskIndex(bobGroup, {}), impl)
    bobGroup = bobProcessMessageResult.newState
  }

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}

async function epochOutOfOrderLimitFails(cipherSuite: CiphersuiteName, totalMessages: number) {
  const retainConfig = { retainKeysForGenerations: 1, retainKeysForEpochs: totalMessages - 1 }
  const {
    aliceGroup: initialAliceGroup,
    bobGroup: initialBobGroup,
    impl,
  } = await setupTestParticipants(cipherSuite, retainConfig)

  let aliceGroup = initialAliceGroup
  let bobGroup = initialBobGroup

  const message = new TextEncoder().encode("Hi!")

  let messages: PrivateMessage[] = []
  for (let i = 0; i < totalMessages; i++) {
    const createMessageResult = await createApplicationMessage(aliceGroup, message, impl)
    // alice sends the first message in current epoch
    aliceGroup = createMessageResult.newState

    // bob creates an empty commit and goes to next epoch
    const emptyCommitResult = await createCommit(bobGroup, emptyPskIndex, false, [], impl)
    bobGroup = emptyCommitResult.newState

    if (emptyCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

    // alice processes the empty commit and goes to next epoch
    const aliceProcessCommitResult = await processPrivateMessage(
      aliceGroup,
      emptyCommitResult.commit.privateMessage,
      emptyPskIndex,
      impl,
    )
    aliceGroup = aliceProcessCommitResult.newState
    messages.push(createMessageResult.privateMessage)
  }

  //process last message
  await expect(processPrivateMessage(bobGroup, messages.at(0)!, emptyPskIndex, impl)).rejects.toThrow()
}
