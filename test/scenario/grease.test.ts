import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { testEveryoneCanMessageEveryone } from "./common.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { defaultGreaseConfig, greaseExtensions } from "../../src/grease.js"
import { Capabilities } from "../../src/capabilities.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`Grease %s`, async (cs) => {
  await greaseTest(cs as CiphersuiteName)
})

async function greaseTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const greased = greaseExtensions(defaultGreaseConfig)
  const caps: Capabilities = {
    ...defaultCapabilities(),
    extensions: greased.map((n) => n.extensionType),
  }
  const alice = await generateKeyPackage(aliceCredential, caps, defaultLifetime, greased, impl)

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

  const bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    unsafeTestingAuthenticationService,
    impl,
    aliceGroup.ratchetTree,
  )

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}
