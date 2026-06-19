import { createGroup, joinGroup } from "../../src/clientState.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"
import { wireformats } from "../../src/wireformat.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"

test.concurrent.each(Object.keys(ciphersuites))(`Commit with GroupContextExtensions proposal %s`, async (cs) => {
  await groupContextExtensionsCommitTest(cs as CiphersuiteName)
})

test.concurrent.each(Object.keys(ciphersuites))(
  `Commit with empty GroupContextExtensions proposal clears extensions %s`,
  async (cs) => {
    await emptyGroupContextExtensionsCommitTest(cs as CiphersuiteName)
  },
)

async function groupContextExtensionsCommitTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage({ credential: charlieCredential, cipherSuite: impl })

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId: new TextEncoder().encode("group1"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const addBob: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: bob.publicPackage },
  }
  const addCharlie: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: charlie.publicPackage },
  }

  const addBothCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [addBob, addCharlie],
    ratchetTreeExtension: true,
  })
  aliceGroup = addBothCommit.newState

  let bobGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    welcome: addBothCommit.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
  })
  let charlieGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    welcome: addBothCommit.welcome!.welcome,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
  })

  const gceProposal: Proposal = {
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions: {
      extensions: [
        {
          extensionType: defaultExtensionTypes.external_senders,
          extensionData: [
            {
              credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode("ext1") },
              signaturePublicKey: new Uint8Array(),
            },
          ],
        },
      ],
    },
  }

  const gceCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [gceProposal],
  })
  aliceGroup = gceCommit.newState

  if (gceCommit.commit.wireformat !== wireformats.mls_private_message) throw new Error("Expected private message")

  const bobProcess = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: gceCommit.commit,
  })
  bobGroup = bobProcess.newState

  const charlieProcess = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: charlieGroup,
    message: gceCommit.commit,
  })
  charlieGroup = charlieProcess.newState

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  expect(
    aliceGroup.groupContext.extensions.some((e) => e.extensionType === defaultExtensionTypes.external_senders),
  ).toBe(true)
  expect(bobGroup.groupContext.extensions.some((e) => e.extensionType === defaultExtensionTypes.external_senders)).toBe(
    true,
  )
  expect(
    charlieGroup.groupContext.extensions.some((e) => e.extensionType === defaultExtensionTypes.external_senders),
  ).toBe(true)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}

async function emptyGroupContextExtensionsCommitTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId: new TextEncoder().encode("group1"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const addBob: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: bob.publicPackage },
  }

  const addBobCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [addBob],
    ratchetTreeExtension: true,
  })
  aliceGroup = addBobCommit.newState

  let bobGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    welcome: addBobCommit.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
  })

  const addExtensions: Proposal = {
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions: {
      extensions: [
        {
          extensionType: defaultExtensionTypes.external_senders,
          extensionData: [
            {
              credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode("ext1") },
              signaturePublicKey: new Uint8Array(),
            },
          ],
        },
      ],
    },
  }

  const addExtensionsCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [addExtensions],
  })
  aliceGroup = addExtensionsCommit.newState

  if (addExtensionsCommit.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const bobAddProcess = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: addExtensionsCommit.commit,
  })
  bobGroup = bobAddProcess.newState

  expect(aliceGroup.groupContext.extensions).toHaveLength(1)
  expect(bobGroup.groupContext.extensions).toHaveLength(1)

  const clearExtensions: Proposal = {
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions: { extensions: [] },
  }

  const clearCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [clearExtensions],
  })
  aliceGroup = clearCommit.newState

  if (clearCommit.commit.wireformat !== wireformats.mls_private_message) throw new Error("Expected private message")

  const bobClearProcess = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: clearCommit.commit,
  })
  bobGroup = bobClearProcess.newState

  expect(aliceGroup.groupContext.extensions).toStrictEqual([])
  expect(bobGroup.groupContext.extensions).toStrictEqual([])
  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}
