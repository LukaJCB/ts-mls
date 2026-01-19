import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { processPrivateMessage } from "../../src/processMessages.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd, ProposalRemove } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { cannotMessageAnymore, testEveryoneCanMessageEveryone } from "./common.js"

import { UsageError } from "../../src/mlsError.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
test.concurrent.each(Object.keys(ciphersuites))(`Remove %s`, async (cs) => {
  await remove(cs as CiphersuiteName)
})

async function remove(cipherSuite: CiphersuiteName) {
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

  const addBobAndCharlieCommitResult = await createCommit({
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

  const removeBobCommitResult = await createCommit({
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

  const bobProcessCommitResult = await processPrivateMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    privateMessage: removeBobCommitResult.commit.privateMessage,
  })

  // bob is removed here
  bobGroup = bobProcessCommitResult.newState

  const charlieProcessCommitResult = await processPrivateMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: charlieGroup,
    privateMessage: removeBobCommitResult.commit.privateMessage,
  })

  charlieGroup = charlieProcessCommitResult.newState

  expect(bobGroup.groupActiveState).toStrictEqual({ kind: "removedFromGroup" })

  //creating a message will fail now
  await expect(
    createCommit({
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
