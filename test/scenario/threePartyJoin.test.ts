import { createGroup, joinGroup, makePskIndex } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { processPrivateMessage } from "../../src/processMessages.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { testEveryoneCanMessageEveryone } from "./common.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
test.concurrent.each(Object.keys(ciphersuites))(`3-party join %s`, async (cs) => {
  await threePartyJoin(cs as CiphersuiteName)
})

async function threePartyJoin(cipherSuite: CiphersuiteName) {
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

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    {
      extraProposals: [addBobProposal],
    },
  )

  aliceGroup = addBobCommitResult.newState

  let bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    unsafeTestingAuthenticationService,
    impl,
    aliceGroup.ratchetTree,
  )

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const addCharlieProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: charlie.publicPackage,
    },
  }

  const addCharlieCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    {
      extraProposals: [addCharlieProposal],
    },
  )

  aliceGroup = addCharlieCommitResult.newState

  if (addCharlieCommitResult.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const processAddCharlieResult = await processPrivateMessage(
    bobGroup,
    addCharlieCommitResult.commit.privateMessage,
    makePskIndex(bobGroup, {}),
    unsafeTestingAuthenticationService,
    impl,
  )

  bobGroup = processAddCharlieResult.newState

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const charlieGroup = await joinGroup(
    addCharlieCommitResult.welcome!,
    charlie.publicPackage,
    charlie.privatePackage,
    emptyPskIndex,
    unsafeTestingAuthenticationService,
    impl,
    aliceGroup.ratchetTree,
  )

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}
