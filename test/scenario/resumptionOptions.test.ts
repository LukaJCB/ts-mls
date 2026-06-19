import { createGroup, joinGroup } from "../../src/clientState.js"
import { branchGroup, joinGroupFromBranch } from "../../src/resumption.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { wireformats } from "../../src/wireformat.js"
import { pskTypes, resumptionPSKUsages } from "../../src/presharedkey.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"

test.concurrent.each(Object.keys(ciphersuites))(`branchGroup honours new options %s`, async (cs) => {
  await branchOptionsTest(cs as CiphersuiteName)
})

test.concurrent.each(Object.keys(ciphersuites))(`Self-resumption PSK in non-resumption commit %s`, async (cs) => {
  await selfResumptionPskTest(cs as CiphersuiteName)
})

async function setupTwoMembers(cipherSuite: CiphersuiteName) {
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
  const addCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [addBob],
    ratchetTreeExtension: true,
  })
  aliceGroup = addCommit.newState
  const bobGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    welcome: addCommit.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
  })

  return { impl, alice, aliceCredential, aliceGroup, bob, bobCredential, bobGroup }
}

async function branchOptionsTest(cipherSuite: CiphersuiteName) {
  const { impl, aliceCredential, aliceGroup, bobCredential, bobGroup } = await setupTwoMembers(cipherSuite)

  const aliceNewKeyPackage = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
  const bobNewKeyPackage = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })

  const branchCommit = await branchGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    keyPackage: aliceNewKeyPackage.publicPackage,
    privateKeyPackage: aliceNewKeyPackage.privatePackage,
    memberKeyPackages: [bobNewKeyPackage.publicPackage],
    newGroupId: new TextEncoder().encode("branch-group"),
    ratchetTreeExtension: true,
    wireAsPublicMessage: true,
  })

  expect(branchCommit.commit.wireformat).toBe(wireformats.mls_public_message)

  const branchedBob = await joinGroupFromBranch({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    oldState: bobGroup,
    welcome: branchCommit.welcome!.welcome,
    keyPackage: bobNewKeyPackage.publicPackage,
    privateKeyPackage: bobNewKeyPackage.privatePackage,
  })

  expect(branchedBob.keySchedule.epochAuthenticator).toStrictEqual(branchCommit.newState.keySchedule.epochAuthenticator)
  await testEveryoneCanMessageEveryone([branchCommit.newState, branchedBob], impl)
}

async function selfResumptionPskTest(cipherSuite: CiphersuiteName) {
  const { impl, aliceGroup, bobGroup } = await setupTwoMembers(cipherSuite)

  // Reference the current group's own resumption PSK (epoch=current).
  const pskNonce = impl.rng.randomBytes(impl.kdf.size)
  const pskProposal: Proposal = {
    proposalType: defaultProposalTypes.psk,
    psk: {
      preSharedKeyId: {
        psktype: pskTypes.resumption,
        usage: resumptionPSKUsages.application,
        pskGroupId: aliceGroup.groupContext.groupId,
        pskEpoch: aliceGroup.groupContext.epoch,
        pskNonce,
      },
    },
  }

  const commit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [pskProposal],
  })

  if (commit.commit.wireformat !== wireformats.mls_private_message) throw new Error("Expected private message")

  const bobAfter = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: commit.commit,
  })

  expect(bobAfter.newState.keySchedule.epochAuthenticator).toStrictEqual(commit.newState.keySchedule.epochAuthenticator)
}
