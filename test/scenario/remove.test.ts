import { createGroup, joinGroup } from "../../src/clientState.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd, ProposalRemove } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import {
  cannotMessageAnymore,
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"

import { UsageError } from "../../src/mlsError.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
test.concurrent.each(Object.keys(ciphersuites))(`Remove %s`, async (cs) => {
  await remove(cs as CiphersuiteName)
})

test("recognizes removal when an Add in the same commit reuses the removed member's leaf", async () => {
  const impl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
  const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
  const makeMember = (identity: string) =>
    generateKeyPackage({
      credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode(identity) },
      cipherSuite: impl,
    })
  const [alice, bob, charlie] = await Promise.all([makeMember("alice"), makeMember("bob"), makeMember("charlie")])
  const initialGroup = await createGroup({
    context,
    groupId: new TextEncoder().encode("remove-and-reuse-leaf"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })
  const addedBob = await createCommitEnsureNoMutation({
    context,
    state: initialGroup,
    extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
  })
  const bobGroup = await joinGroup({
    context,
    welcome: addedBob.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: addedBob.newState.ratchetTree,
  })

  const replacedBob = await createCommitEnsureNoMutation({
    context,
    state: addedBob.newState,
    extraProposals: [
      { proposalType: defaultProposalTypes.remove, remove: { removed: bobGroup.privatePath.leafIndex } },
      { proposalType: defaultProposalTypes.add, add: { keyPackage: charlie.publicPackage } },
    ],
  })
  const charlieGroup = await joinGroup({
    context,
    welcome: replacedBob.welcome!.welcome,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
    ratchetTree: replacedBob.newState.ratchetTree,
  })
  expect(charlieGroup.privatePath.leafIndex).toBe(bobGroup.privatePath.leafIndex)

  const removedBob = await processMessageEnsureNoMutation({ context, state: bobGroup, message: replacedBob.commit })
  expect(removedBob.newState.groupActiveState).toStrictEqual({ kind: "removedFromGroup" })
  await cannotMessageAnymore(removedBob.newState, impl)
  await testEveryoneCanMessageEveryone([replacedBob.newState, charlieGroup], impl)
})

test("removes the left subtree while preserving communication in the right subtree", async () => {
  const impl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
  const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
  const makeMember = (identity: string) =>
    generateKeyPackage({
      credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode(identity) },
      cipherSuite: impl,
    })
  const [alice, bob, charlie, dave] = await Promise.all([
    makeMember("alice"),
    makeMember("bob"),
    makeMember("charlie"),
    makeMember("dave"),
  ])
  const initialGroup = await createGroup({
    context,
    groupId: new TextEncoder().encode("remove-left-subtree"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })
  const added = await createCommitEnsureNoMutation({
    context,
    state: initialGroup,
    extraProposals: [bob, charlie, dave].map((member): ProposalAdd => ({
      proposalType: defaultProposalTypes.add,
      add: { keyPackage: member.publicPackage },
    })),
  })
  const joinMember = (member: typeof charlie) =>
    joinGroup({
      context,
      welcome: added.welcome!.welcome,
      keyPackage: member.publicPackage,
      privateKeys: member.privatePackage,
      ratchetTree: added.newState.ratchetTree,
    })
  const charlieGroup = await joinMember(charlie)
  const daveGroup = await joinMember(dave)

  // Remove leaves 0 and 1 together, leaving leaves 2 and 3 under a blank root at node 3.
  const removed = await createCommitEnsureNoMutation({
    context,
    state: charlieGroup,
    extraProposals: [0, 1].map((removed): ProposalRemove => ({
      proposalType: defaultProposalTypes.remove,
      remove: { removed },
    })),
  })
  const received = await processMessageEnsureNoMutation({ context, state: daveGroup, message: removed.commit })

  expect(removed.newState.ratchetTree[3]).toBeUndefined()
  expect(received.newState.groupContext.treeHash).toStrictEqual(removed.newState.groupContext.treeHash)
  expect(received.newState.privatePath.privateKeys[3]).toBeUndefined()
  expect(received.newState.keySchedule.epochAuthenticator).toStrictEqual(
    removed.newState.keySchedule.epochAuthenticator,
  )
  await testEveryoneCanMessageEveryone([removed.newState, received.newState], impl)
})

async function remove(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

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

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage({
    credential: charlieCredential,
    cipherSuite: impl,
  })

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addCharlieProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: charlie.publicPackage,
    },
  }

  const addBobAndCharlieCommitResult = await createCommitEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [addBobProposal, addCharlieProposal],
  })

  aliceGroup = addBobAndCharlieCommitResult.newState

  let bobGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: addBobAndCharlieCommitResult.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  let charlieGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: addBobAndCharlieCommitResult.welcome!.welcome,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const removeBobProposal: ProposalRemove = {
    proposalType: defaultProposalTypes.remove,
    remove: {
      removed: bobGroup.privatePath.leafIndex,
    },
  }

  const removeBobCommitResult = await createCommitEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [removeBobProposal],
  })

  aliceGroup = removeBobCommitResult.newState

  if (removeBobCommitResult.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const bobProcessCommitResult = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    message: removeBobCommitResult.commit,
  })

  // bob is removed here
  bobGroup = bobProcessCommitResult.newState

  const charlieProcessCommitResult = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: charlieGroup,
    message: removeBobCommitResult.commit,
  })

  charlieGroup = charlieProcessCommitResult.newState

  expect(bobGroup.groupActiveState).toStrictEqual({ kind: "removedFromGroup" })

  //creating a message will fail now
  await expect(
    createCommitEnsureNoMutation({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: bobGroup,
    }),
  ).rejects.toThrow(UsageError)

  await cannotMessageAnymore(bobGroup, impl)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, charlieGroup], impl)
}
