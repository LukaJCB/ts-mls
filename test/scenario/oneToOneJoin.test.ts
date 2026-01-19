import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { createApplicationMessage } from "../../src/createMessage.js"
import { processMessage } from "../../src/processMessages.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { mlsMessageDecoder, mlsMessageEncoder } from "../../src/message.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"

import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { protocolVersions } from "../../src/protocolVersion.js"
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
  const commitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [addBobProposal],
  })

  aliceGroup = commitResult.newState

  // alice sends welcome message to bob
  const encodedWelcome = encode(mlsMessageEncoder, {
    welcome: commitResult.welcome!.welcome,
    wireformat: wireformats.mls_welcome,
    version: protocolVersions.mls10,
  })

  // bob decodes the welcome message
  const decodedWelcome = mlsMessageDecoder(encodedWelcome, 0)![0]

  if (decodedWelcome.wireformat !== wireformats.mls_welcome) throw new Error("Expected welcome")

  // bob creates his own group state
  let bobGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: decodedWelcome.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  // ensure epochAuthenticator values are equal
  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const messageToBob = new TextEncoder().encode("Hello bob!")

  // alice creates a message to the group
  const aliceCreateMessageResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    message: messageToBob,
  })

  aliceGroup = aliceCreateMessageResult.newState

  // alice sends the message to bob
  const encodedPrivateMessageAlice = encode(mlsMessageEncoder, aliceCreateMessageResult.message)

  // bob decodes the message
  const decodedPrivateMessageAlice = mlsMessageDecoder(encodedPrivateMessageAlice, 0)![0]

  if (decodedPrivateMessageAlice.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  // bob receives the message
  const bobProcessMessageResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    message: decodedPrivateMessageAlice,
  })

  bobGroup = bobProcessMessageResult.newState

  if (bobProcessMessageResult.kind === "newState") throw new Error("Expected application message")

  expect(bobProcessMessageResult.message).toStrictEqual(messageToBob)

  const messageToAlice = new TextEncoder().encode("Hello alice!")

  const bobCreateMessageResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: messageToAlice,
  })

  bobGroup = bobCreateMessageResult.newState

  const encodedPrivateMessageBob = encode(mlsMessageEncoder, bobCreateMessageResult.message)

  const decodedPrivateMessageBob = mlsMessageDecoder(encodedPrivateMessageBob, 0)![0]

  if (decodedPrivateMessageBob.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const aliceProcessMessageResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    message: decodedPrivateMessageBob,
  })

  aliceGroup = aliceProcessMessageResult.newState

  if (aliceProcessMessageResult.kind === "newState") throw new Error("Expected application message")

  expect(aliceProcessMessageResult.message).toStrictEqual(messageToAlice)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
}
