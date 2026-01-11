import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { createProposal } from "../../src/index.js"
import { processMessage } from "../../src/processMessages.js"
import { encodeExternalSender } from "../../src/externalSender.js"
import { WireformatName } from "../../src/wireformat.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"

test.concurrent.each(Object.keys(ciphersuites))(`Reject incoming message %s`, async (cs) => {
  await rejectIncomingMessagesTest(cs as CiphersuiteName, true)
  await rejectIncomingMessagesTest(cs as CiphersuiteName, false)
})

async function rejectIncomingMessagesTest(cipherSuite: CiphersuiteName, publicMessage: boolean) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")
  const preferredWireformat: WireformatName = publicMessage ? "mls_public_message" : "mls_private_message"

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

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
    },
    {
      wireAsPublicMessage: publicMessage,
      extraProposals: [addBobProposal],
    },
  )

  aliceGroup = addBobCommitResult.newState

  let bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  const bobProposeExtensions: Proposal = {
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions: {
      extensions: [
        {
          extensionType: defaultExtensionTypes.external_senders,
          extensionData: encodeExternalSender({
            credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array() },
            signaturePublicKey: new Uint8Array(),
          }),
        },
      ],
    },
  }

  const createExtensionsProposalResults = await createProposal(bobGroup, publicMessage, bobProposeExtensions, impl)

  bobGroup = createExtensionsProposalResults.newState

  if (createExtensionsProposalResults.message.wireformat !== preferredWireformat)
    throw new Error(`Expected ${preferredWireformat} message`)

  //alice rejects the proposal
  const aliceRejectsProposalResult = await processMessage(
    createExtensionsProposalResults.message,
    aliceGroup,
    emptyPskIndex,
    () => "reject",
    impl,
  )

  aliceGroup = aliceRejectsProposalResult.newState

  expect(aliceGroup.unappliedProposals).toStrictEqual({})

  // alice commits without the proposal
  const aliceCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    {
      wireAsPublicMessage: publicMessage,
    },
  )

  aliceGroup = aliceCommitResult.newState

  if (aliceCommitResult.commit.wireformat !== preferredWireformat)
    throw new Error(`Expected ${preferredWireformat} message`)

  const bobRejectsAliceCommitResult = await processMessage(
    aliceCommitResult.commit,
    bobGroup,
    emptyPskIndex,
    () => "reject",
    impl,
  )

  // group context and keySchedule haven't changed since bob rejected the commit
  expect(bobRejectsAliceCommitResult.newState.groupContext).toStrictEqual(bobGroup.groupContext)
  expect(bobRejectsAliceCommitResult.newState.keySchedule).toStrictEqual(bobGroup.keySchedule)
}
