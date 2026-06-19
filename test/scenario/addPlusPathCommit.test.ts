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
import { wireformats } from "../../src/wireformat.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"

test.concurrent.each(Object.keys(ciphersuites))(`Add + path commit excludes new leaves %s`, async (cs) => {
  await addPlusPathCommitTest(cs as CiphersuiteName)
})

async function addPlusPathCommitTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const daveCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("dave"),
  }

  const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
  const bob = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })
  const charlie = await generateKeyPackage({ credential: charlieCredential, cipherSuite: impl })
  const dave = await generateKeyPackage({ credential: daveCredential, cipherSuite: impl })

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId: new TextEncoder().encode("group1"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  // Add Bob first (add-only commit, no path update).
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

  const addCharlie: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: charlie.publicPackage },
  }
  const addDave: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: dave.publicPackage },
  }
  const gce: Proposal = {
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions: {
      extensions: [
        {
          extensionType: defaultExtensionTypes.external_senders,
          extensionData: [
            {
              credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode("ext") },
              signaturePublicKey: new Uint8Array(),
            },
          ],
        },
      ],
    },
  }

  const bigCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [addCharlie, addDave, gce],
    ratchetTreeExtension: true,
  })
  aliceGroup = bigCommit.newState

  if (bigCommit.commit.wireformat !== wireformats.mls_private_message) throw new Error("Expected private message")

  const bobAfter = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: bigCommit.commit,
  })
  bobGroup = bobAfter.newState

  const charlieGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    welcome: bigCommit.welcome!.welcome,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
  })

  const daveGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    welcome: bigCommit.welcome!.welcome,
    keyPackage: dave.publicPackage,
    privateKeys: dave.privatePackage,
  })

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(daveGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await checkHpkeKeysMatch(daveGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup, daveGroup], impl)
}
