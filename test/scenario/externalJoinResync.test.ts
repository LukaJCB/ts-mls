import { createGroup, getOwnLeafNode, joinGroup } from "../../src/clientState.js"
import { createGroupInfoWithExternalPubAndRatchetTree, joinGroupExternal } from "../../src/createCommit.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage, generateKeyPackageWithKey } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"

import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { ValidationError } from "../../src/mlsError.js"

test.concurrent.each(Object.keys(ciphersuites))(`External join Resync %s`, async (cs) => {
  await externalJoinResyncTest(cs as CiphersuiteName)
  await externalJoinResyncTestThrows(cs as CiphersuiteName)
  await externalJoinResyncSingleMemberTest(cs as CiphersuiteName)
})

async function externalJoinResyncSingleMemberTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)
  const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
  const initialGroup = await createGroup({
    context,
    groupId: new TextEncoder().encode("singleton-resync"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })
  expect(initialGroup.ratchetTree).toHaveLength(1)
  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(initialGroup, [], impl)

  // Recover using fresh keys for the same identity without supplying the old group state
  const replacement = await generateKeyPackageWithKey({
    credential: aliceCredential,
    cipherSuite: impl,
    signatureKeyPair: {
      publicKey: alice.publicPackage.leafNode.signaturePublicKey,
      signKey: alice.privatePackage.signaturePrivateKey,
    },
  })
  const resynced = await joinGroupExternal({
    context,
    groupInfo,
    keyPackage: replacement.publicPackage,
    privateKeys: replacement.privatePackage,
    resync: true,
  })

  expect(resynced.newState.ratchetTree).toHaveLength(1)
  expect(resynced.newState.privatePath.leafIndex).toBe(0)
  expect(resynced.newState.groupContext.groupId).toStrictEqual(groupInfo.groupContext.groupId)
  expect(resynced.newState.groupContext.epoch).toBe(groupInfo.groupContext.epoch + 1n)
  expect(getOwnLeafNode(resynced.newState).signaturePublicKey).toStrictEqual(
    replacement.publicPackage.leafNode.signaturePublicKey,
  )
  expect(resynced.commit.publicMessage.content).toMatchObject({
    commit: {
      proposals: [
        { proposal: { proposalType: defaultProposalTypes.remove, remove: { removed: 0 } } },
        { proposal: { proposalType: defaultProposalTypes.external_init } },
      ],
      path: { nodes: [] },
    },
  })
  await checkHpkeKeysMatch(resynced.newState, impl)

  const bob = await generateKeyPackage({
    cipherSuite: impl,
    credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode("bob") },
  })
  const addedBob = await createCommitEnsureNoMutation({
    context,
    state: resynced.newState,
    extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
    ratchetTreeExtension: true,
  })
  const bobGroup = await joinGroup({
    context,
    welcome: addedBob.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
  })
  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(addedBob.newState.keySchedule.epochAuthenticator)
  await testEveryoneCanMessageEveryone([addedBob.newState, bobGroup], impl)
}

async function externalJoinResyncTestThrows(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })

  const aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId: new TextEncoder().encode("group1"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)

  // Bob has never been a member. Resync must fail fast, not infinite-loop on findIndex(-1).
  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })

  await expect(
    joinGroupExternal({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      groupInfo,
      keyPackage: bob.publicPackage,
      privateKeys: bob.privatePackage,
      resync: true,
    }),
  ).rejects.toThrow(new ValidationError("External join with resync: no prior leaf matching the new KeyPackage"))
}

async function externalJoinResyncTest(cipherSuite: CiphersuiteName) {
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
    ratchetTreeExtension: true,
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
  })

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(charlieGroup, [], impl)

  const charlieResyncCommitResult = await joinGroupExternal({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    groupInfo,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
    resync: true,
  })

  charlieGroup = charlieResyncCommitResult.newState

  const aliceProcessCharlieResyncResult = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    message: charlieResyncCommitResult.commit,
  })

  aliceGroup = aliceProcessCharlieResyncResult.newState

  const bobProcessCharlieResyncResult = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    message: charlieResyncCommitResult.commit,
  })

  bobGroup = bobProcessCharlieResyncResult.newState

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(bobGroup.keySchedule.epochAuthenticator)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}
