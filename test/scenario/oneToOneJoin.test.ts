import { createGroup, joinGroup, makePskIndex } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { createApplicationMessage } from "../../src/createMessage.js"
import { processPrivateMessage } from "../../src/processMessages.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { mlsMessageDecoder, mlsMessageEncoder } from "../../src/message.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
test.concurrent.each(Object.keys(ciphersuites))(`1:1 join %s`, async (cs) => {
  await oneToOne(cs as CiphersuiteName)
})

async function oneToOne(cipherSuite: CiphersuiteName) {
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

  // bob sends keyPackage to alice
  const keyPackageMessage = encode(mlsMessageEncoder, {
    keyPackage: bob.publicPackage,
    wireformat: wireformats.mls_key_package,
    version: protocolVersions.mls10,
  })

  // alice decodes bob's keyPackage
  const decodedKeyPackage = mlsMessageDecoder(keyPackageMessage, 0)![0]

  if (decodedKeyPackage.wireformat !== wireformats.mls_key_package) throw new Error("Expected key package")

  // alice creates proposal to add bob
  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: decodedKeyPackage.keyPackage,
    },
  }

  // alice commits
  const commitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    {
      extraProposals: [addBobProposal],
    },
  )

  aliceGroup = commitResult.newState

  // alice sends welcome message to bob
  const encodedWelcome = encode(mlsMessageEncoder, {
    welcome: commitResult.welcome!,
    wireformat: wireformats.mls_welcome,
    version: protocolVersions.mls10,
  })

  // bob decodes the welcome message
  const decodedWelcome = mlsMessageDecoder(encodedWelcome, 0)![0]

  if (decodedWelcome.wireformat !== wireformats.mls_welcome) throw new Error("Expected welcome")

  // bob creates his own group state
  let bobGroup = await joinGroup(
    decodedWelcome.welcome,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    unsafeTestingAuthenticationService,
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
  const encodedPrivateMessageAlice = encode(mlsMessageEncoder, {
    privateMessage: aliceCreateMessageResult.privateMessage,
    wireformat: wireformats.mls_private_message,
    version: protocolVersions.mls10,
  })

  // bob decodes the message
  const decodedPrivateMessageAlice = mlsMessageDecoder(encodedPrivateMessageAlice, 0)![0]

  if (decodedPrivateMessageAlice.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  // bob receives the message
  const bobProcessMessageResult = await processPrivateMessage(
    bobGroup,
    decodedPrivateMessageAlice.privateMessage,
    makePskIndex(bobGroup, {}),
    unsafeTestingAuthenticationService,
    impl,
  )

  bobGroup = bobProcessMessageResult.newState

  if (bobProcessMessageResult.kind === "newState") throw new Error("Expected application message")

  expect(bobProcessMessageResult.message).toStrictEqual(messageToBob)

  const messageToAlice = new TextEncoder().encode("Hello alice!")

  const bobCreateMessageResult = await createApplicationMessage(bobGroup, messageToAlice, impl)

  bobGroup = bobCreateMessageResult.newState

  const encodedPrivateMessageBob = encode(mlsMessageEncoder, {
    privateMessage: bobCreateMessageResult.privateMessage,
    wireformat: wireformats.mls_private_message,
    version: protocolVersions.mls10,
  })

  const decodedPrivateMessageBob = mlsMessageDecoder(encodedPrivateMessageBob, 0)![0]

  if (decodedPrivateMessageBob.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const aliceProcessMessageResult = await processPrivateMessage(
    aliceGroup,
    decodedPrivateMessageBob.privateMessage,
    makePskIndex(aliceGroup, {}),
    unsafeTestingAuthenticationService,
    impl,
  )

  aliceGroup = aliceProcessMessageResult.newState

  if (aliceProcessMessageResult.kind === "newState") throw new Error("Expected application message")

  expect(aliceProcessMessageResult.message).toStrictEqual(messageToAlice)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
}
