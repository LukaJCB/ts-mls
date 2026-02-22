import { createGroup, joinGroup } from "../../src/clientState.js"
import { joinGroupFromReinit, reinitCreateNewGroup, reinitGroup } from "../../src/resumption.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import {
  createCommitEnsureNoMutation,
  getRandomElement,
  processPrivateMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"

import { UsageError } from "../../src/mlsError.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
test.concurrent.each(Object.keys(ciphersuites))(`Reinit %s`, async (cs) => {
  await reinit(cs as CiphersuiteName)
})

async function reinit(cipherSuite: CiphersuiteName) {
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

  const newCiphersuite = getRandomElement(Object.keys(ciphersuites)) as CiphersuiteName

  const newGroupId = new TextEncoder().encode("new-group1")

  const reinitCommitResult = await reinitGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    groupId: newGroupId,
    version: "mls10",
    cipherSuite: newCiphersuite,
  })

  aliceGroup = reinitCommitResult.newState

  if (reinitCommitResult.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const processReinitResult = await processPrivateMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    privateMessage: reinitCommitResult.commit.privateMessage,
  })

  bobGroup = processReinitResult.newState

  expect(bobGroup.groupActiveState.kind).toBe("suspendedPendingReinit")
  expect(aliceGroup.groupActiveState.kind).toBe("suspendedPendingReinit")

  //creating a message will fail now
  await expect(
    createCommitEnsureNoMutation({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: aliceGroup,
    }),
  ).rejects.toThrow(UsageError)

  const newImpl = await getCiphersuiteImpl(newCiphersuite)

  const bobNewKeyPackage = await generateKeyPackage({
    credential: bobCredential,
    cipherSuite: newImpl,
  })

  const aliceNewKeyPackage = await generateKeyPackage({
    credential: aliceCredential,
    cipherSuite: newImpl,
  })

  const resumeGroupResult = await reinitCreateNewGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    keyPackage: aliceNewKeyPackage.publicPackage,
    privateKeyPackage: aliceNewKeyPackage.privatePackage,
    memberKeyPackages: [bobNewKeyPackage.publicPackage],
    groupId: newGroupId,
    cipherSuite: newCiphersuite,
  })

  aliceGroup = resumeGroupResult.newState

  bobGroup = await joinGroupFromReinit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    suspendedState: bobGroup,
    welcome: resumeGroupResult.welcome!.welcome,
    keyPackage: bobNewKeyPackage.publicPackage,
    privateKeyPackage: bobNewKeyPackage.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], newImpl)
  await checkHpkeKeysMatch(aliceGroup, newImpl)
  await checkHpkeKeysMatch(bobGroup, newImpl)
}
