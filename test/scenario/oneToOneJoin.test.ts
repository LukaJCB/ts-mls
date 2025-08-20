import { createGroup, joinGroup, makePskIndex } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { createApplicationMessage } from "../../src/createMessage"
import { processPrivateMessage } from "../../src/processMessages"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { generateKeyPackage } from "../../src/keyPackage"
import { decodeMlsMessage, encodeMlsMessage } from "../../src/message"
import { ProposalAdd } from "../../src/proposal"
import { checkHpkeKeysMatch } from "../crypto/keyMatch"
import { defaultLifetime } from "../../src/lifetime"
import { defaultCapabilities } from "../../src/defaultCapabilities"

for (const cs of Object.keys(ciphersuites)) {
  test(`1:1 join ${cs}`, async () => {
    await oneToOne(cs as CiphersuiteName)
  })
}

async function oneToOne(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  // bob sends keyPackage to alice
  const keyPackageMessage = encodeMlsMessage({
    keyPackage: bob.publicPackage,
    wireformat: "mls_key_package",
    version: "mls10",
  })

  // alice decodes bob's keyPackage
  const decodedKeyPackage = decodeMlsMessage(keyPackageMessage, 0)![0]

  if (decodedKeyPackage.wireformat !== "mls_key_package") throw new Error("Expected key package")

  // alice creates proposal to add bob
  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: decodedKeyPackage.keyPackage,
    },
  }

  // alice commits
  const commitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)

  aliceGroup = commitResult.newState

  // alice sends welcome message to bob
  const encodedWelcome = encodeMlsMessage({
    welcome: commitResult.welcome!,
    wireformat: "mls_welcome",
    version: "mls10",
  })

  // bob decodes the welcome message
  const decodedWelcome = decodeMlsMessage(encodedWelcome, 0)![0]

  if (decodedWelcome.wireformat !== "mls_welcome") throw new Error("Expected welcome")

  // bob creates his own group state
  let bobGroup = await joinGroup(
    decodedWelcome.welcome,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  // ensure epochAuthenticator values are equal
  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const messageToBob = new TextEncoder().encode("Hello bob!")

  // alice creates a message to the group
  const aliceCreateMessageResult = await createApplicationMessage(aliceGroup, messageToBob, impl)

  aliceGroup = aliceCreateMessageResult.newState

  // alice sends the message to bob
  const encodedPrivateMessageAlice = encodeMlsMessage({
    privateMessage: aliceCreateMessageResult.privateMessage,
    wireformat: "mls_private_message",
    version: "mls10",
  })

  // bob decodes the message
  const decodedPrivateMessageAlice = decodeMlsMessage(encodedPrivateMessageAlice, 0)![0]

  if (decodedPrivateMessageAlice.wireformat !== "mls_private_message") throw new Error("Expected private message")

  // bob receives the message
  const bobProcessMessageResult = await processPrivateMessage(
    bobGroup,
    decodedPrivateMessageAlice.privateMessage,
    makePskIndex(bobGroup, {}),
    impl,
  )

  bobGroup = bobProcessMessageResult.newState

  if (bobProcessMessageResult.kind === "newState") throw new Error("Expected application message")

  expect(bobProcessMessageResult.message).toStrictEqual(messageToBob)

  const messageToAlice = new TextEncoder().encode("Hello alice!")

  const bobCreateMessageResult = await createApplicationMessage(bobGroup, messageToAlice, impl)

  bobGroup = bobCreateMessageResult.newState

  const encodedPrivateMessageBob = encodeMlsMessage({
    privateMessage: bobCreateMessageResult.privateMessage,
    wireformat: "mls_private_message",
    version: "mls10",
  })

  const decodedPrivateMessageBob = decodeMlsMessage(encodedPrivateMessageBob, 0)![0]

  if (decodedPrivateMessageBob.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const aliceProcessMessageResult = await processPrivateMessage(
    aliceGroup,
    decodedPrivateMessageBob.privateMessage,
    makePskIndex(aliceGroup, {}),
    impl,
  )

  aliceGroup = aliceProcessMessageResult.newState

  if (aliceProcessMessageResult.kind === "newState") throw new Error("Expected application message")

  expect(aliceProcessMessageResult.message).toStrictEqual(messageToAlice)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
}
