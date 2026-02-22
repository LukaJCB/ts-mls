import { createGroup, joinGroup } from "../../src/clientState.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"

import { createProposal, unsafeTestingAuthenticationService } from "../../src/index.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { wireformats } from "../../src/wireformat.js"
import { createCommitEnsureNoMutation, processMessageEnsureNoMutation } from "./common.js"
test.concurrent.each(Object.keys(ciphersuites))(`Reject incoming message %s`, async (cs) => {
  await rejectIncomingMessagesTest(cs as CiphersuiteName, true)
  await rejectIncomingMessagesTest(cs as CiphersuiteName, false)
})

async function rejectIncomingMessagesTest(cipherSuite: CiphersuiteName, publicMessage: boolean) {
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
  const preferredWireformat = publicMessage ? wireformats.mls_public_message : wireformats.mls_private_message

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

  const addBobCommitResult = await createCommitEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    wireAsPublicMessage: publicMessage,
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

  const bobProposeExtensions: Proposal = {
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions: {
      extensions: [
        {
          extensionType: defaultExtensionTypes.external_senders,
          extensionData: {
            credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array() },
            signaturePublicKey: new Uint8Array(),
          },
        },
      ],
    },
  }

  const createExtensionsProposalResults = await createProposal({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    wireAsPublicMessage: publicMessage,
    proposal: bobProposeExtensions,
  })

  bobGroup = createExtensionsProposalResults.newState

  if (createExtensionsProposalResults.message.wireformat !== preferredWireformat)
    throw new Error(`Expected ${preferredWireformat} message`)

  //alice rejects the proposal
  const aliceRejectsProposalResult = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    message: createExtensionsProposalResults.message,
    callback: () => "reject",
  })

  aliceGroup = aliceRejectsProposalResult.newState

  expect(aliceGroup.unappliedProposals).toStrictEqual({})

  // alice commits without the proposal
  const aliceCommitResult = await createCommitEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    wireAsPublicMessage: publicMessage,
  })

  aliceGroup = aliceCommitResult.newState

  if (aliceCommitResult.commit.wireformat !== preferredWireformat)
    throw new Error(`Expected ${preferredWireformat} message`)

  const bobRejectsAliceCommitResult = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    message: aliceCommitResult.commit,
    callback: () => "reject",
  })

  // group context and keySchedule haven't changed since bob rejected the commit
  expect(bobRejectsAliceCommitResult.newState.groupContext).toStrictEqual(bobGroup.groupContext)
  expect(bobRejectsAliceCommitResult.newState.keySchedule).toStrictEqual(bobGroup.keySchedule)
}
