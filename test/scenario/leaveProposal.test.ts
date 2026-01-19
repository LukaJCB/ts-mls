import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { createProposal } from "../../src/createMessage.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { cannotMessageAnymore, testEveryoneCanMessageEveryone } from "./common.js"

import { processMessage } from "../../src/processMessages.js"
import { acceptAll } from "../../src/incomingMessageAction.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
test.concurrent.each(Object.keys(ciphersuites))(`Leave Proposal %s`, async (cs) => {
  await leaveProposal(cs as CiphersuiteName, true)
  await leaveProposal(cs as CiphersuiteName, false)
})

async function leaveProposal(cipherSuite: CiphersuiteName, publicMessage: boolean) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({
    credential: aliceCredential,
    cipherSuite: impl,
  })

  const preferredWireformat = publicMessage ? wireformats.mls_public_message : wireformats.mls_private_message
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
    wireAsPublicMessage: publicMessage,
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

  const leaveProposal: Proposal = {
    proposalType: defaultProposalTypes.remove,
    remove: { removed: aliceGroup.privatePath.leafIndex },
  }

  const createLeaveProposalResult = await createProposal({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    wireAsPublicMessage: publicMessage,
    proposal: leaveProposal,
  })

  aliceGroup = createLeaveProposalResult.newState

  if (createLeaveProposalResult.message.wireformat !== preferredWireformat)
    throw new Error(`Expected ${preferredWireformat} message`)

  const bobProcessProposalResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      pskIndex: emptyPskIndex,
    },
    state: bobGroup,
    message: createLeaveProposalResult.message,
    callback: acceptAll,
  })

  bobGroup = bobProcessProposalResult.newState

  const charlieProcessProposalResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      pskIndex: emptyPskIndex,
    },
    state: charlieGroup,
    message: createLeaveProposalResult.message,
    callback: acceptAll,
  })

  charlieGroup = charlieProcessProposalResult.newState

  //bob commits to alice leaving
  const bobCommitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    wireAsPublicMessage: publicMessage,
    ratchetTreeExtension: false,
  })

  bobGroup = bobCommitResult.newState

  if (bobCommitResult.commit.wireformat !== preferredWireformat)
    throw new Error(`Expected ${preferredWireformat} message`)

  const aliceProcessCommitResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      pskIndex: emptyPskIndex,
    },
    state: aliceGroup,
    message: bobCommitResult.commit,
    callback: acceptAll,
  })
  aliceGroup = aliceProcessCommitResult.newState

  const charlieProcessCommitResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      pskIndex: emptyPskIndex,
    },
    state: charlieGroup,
    message: bobCommitResult.commit,
    callback: acceptAll,
  })
  charlieGroup = charlieProcessCommitResult.newState

  expect(bobGroup.unappliedProposals).toEqual({})
  expect(charlieGroup.unappliedProposals).toEqual({})
  expect(aliceGroup.groupActiveState).toStrictEqual({ kind: "removedFromGroup" })

  await cannotMessageAnymore(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([bobGroup, charlieGroup], impl)
}
