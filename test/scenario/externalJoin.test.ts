import { createGroup, joinGroup } from "../../src/clientState.js"
import { createGroupInfoWithExternalPubAndRatchetTree, joinGroupExternal } from "../../src/createCommit.js"
import { createCommit } from "../../src/createCommit.js"
import { processPublicMessage } from "../../src/processMessages.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { testEveryoneCanMessageEveryone } from "./common.js"

import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`External join %s`, async (cs) => {
  await externalJoin(cs as CiphersuiteName)
})

async function externalJoin(cipherSuite: CiphersuiteName) {
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

  const addBobCommitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [addBobProposal],
  })

  aliceGroup = addBobCommitResult.newState

  let bobGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: addBobCommitResult.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)

  const charlieJoinGroupCommitResult = await joinGroupExternal({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    groupInfo,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
    resync: false,
  })

  const charlieGroup = charlieJoinGroupCommitResult.newState

  const aliceProcessCharlieJoinResult = await processPublicMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    publicMessage: charlieJoinGroupCommitResult.publicMessage,
  })

  aliceGroup = aliceProcessCharlieJoinResult.newState

  const bobProcessCharlieJoinResult = await processPublicMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    publicMessage: charlieJoinGroupCommitResult.publicMessage,
  })

  bobGroup = bobProcessCharlieJoinResult.newState

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(bobGroup.keySchedule.epochAuthenticator)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}
