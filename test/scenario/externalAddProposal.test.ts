import { createGroup, joinGroup } from "../../src/clientState.js"
import { createGroupInfoWithExternalPub } from "../../src/createCommit.js"
import { createCommit } from "../../src/createCommit.js"
import { processPrivateMessage, processPublicMessage } from "../../src/processMessages.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { testEveryoneCanMessageEveryone } from "./common.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { encodeExternalSender, ExternalSender } from "../../src/externalSender.js"
import { Extension } from "../../src/extension.js"
import { proposeAddExternal } from "../../src/externalProposal.js"

test.concurrent.each(Object.keys(ciphersuites))(`External Add Proposal %s`, async (cs) => {
  await externalAddProposalTest(cs as CiphersuiteName)
})

async function externalAddProposalTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    { extraProposals: [addBobProposal] },
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

  // external pub not really necessary here
  const groupInfo = await createGroupInfoWithExternalPub(aliceGroup, [], impl)

  const addCharlieProposal = await proposeAddExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, impl)

  if (addCharlieProposal.wireformat !== "mls_public_message") throw new Error("Expected public message")

  const aliceProcessCharlieProposalResult = await processPublicMessage(
    aliceGroup,
    addCharlieProposal.publicMessage,
    emptyPskIndex,
    impl,
  )

  aliceGroup = aliceProcessCharlieProposalResult.newState

  const bobProcessCharlieProposalResult = await processPublicMessage(
    bobGroup,
    addCharlieProposal.publicMessage,
    emptyPskIndex,
    impl,
  )

  bobGroup = bobProcessCharlieProposalResult.newState

  const addCharlieCommitResult = await createCommit({
    state: aliceGroup,
    cipherSuite: impl,
  })

  aliceGroup = addCharlieCommitResult.newState

  if (addCharlieCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const processAddCharlieResult = await processPrivateMessage(
    bobGroup,
    addCharlieCommitResult.commit.privateMessage,
    emptyPskIndex,
    impl,
  )

  bobGroup = processAddCharlieResult.newState

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const charlieGroup = await joinGroup(
    addCharlieCommitResult.welcome!,
    charlie.publicPackage,
    charlie.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}
