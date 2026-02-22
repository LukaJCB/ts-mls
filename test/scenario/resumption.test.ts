import { createGroup, joinGroup } from "../../src/clientState.js"
import { branchGroup, joinGroupFromBranch } from "../../src/resumption.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { createCommitEnsureNoMutation, testEveryoneCanMessageEveryone } from "./common.js"

import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`Resumption %s`, async (cs) => {
  await resumption(cs as CiphersuiteName)
})

async function resumption(cipherSuite: CiphersuiteName) {
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

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const commitResult = await createCommitEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [addBobProposal],
  })

  aliceGroup = commitResult.newState

  let bobGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: commitResult.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  const bobNewKeyPackage = await generateKeyPackage({
    credential: bobCredential,
    cipherSuite: impl,
  })

  const aliceNewKeyPackage = await generateKeyPackage({
    credential: aliceCredential,
    cipherSuite: impl,
  })

  const newGroupId = new TextEncoder().encode("new-group1")

  const branchCommitResult = await branchGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    keyPackage: aliceNewKeyPackage.publicPackage,
    privateKeyPackage: aliceNewKeyPackage.privatePackage,
    memberKeyPackages: [bobNewKeyPackage.publicPackage],
    newGroupId,
  })

  aliceGroup = branchCommitResult.newState

  bobGroup = await joinGroupFromBranch({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    oldState: bobGroup,
    welcome: branchCommitResult.welcome!.welcome,
    keyPackage: bobNewKeyPackage.publicPackage,
    privateKeyPackage: bobNewKeyPackage.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
}
