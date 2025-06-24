import { createGroup, joinGroup } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { createProposal } from "../../src/createMessage"
import { processPrivateMessage } from "../../src/processMessages"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { Proposal, ProposalAdd } from "../../src/proposal"
import { checkHpkeKeysMatch } from "../crypto/keyMatch"
import { defaultCapabilities, defaultLifetime, testEveryoneCanMessageEveryone } from "./common"

for (const cs of Object.keys(ciphersuites).slice(0, 1)) {
  test(`Leave Proposal ${cs}`, async () => {
    await leaveProposal(cs as CiphersuiteName)
  })
}

async function leaveProposal(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

  const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities, defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addCharlieProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: charlie.publicPackage,
    },
  }

  const addBobAndCharlieCommitResult = await createCommit(
    aliceGroup,
    emptyPskIndex,
    false,
    [addBobProposal, addCharlieProposal],
    impl,
    true,
  )

  aliceGroup = addBobAndCharlieCommitResult.newState

  let bobGroup = await joinGroup(
    addBobAndCharlieCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
  )

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  let charlieGroup = await joinGroup(
    addBobAndCharlieCommitResult.welcome!,
    charlie.publicPackage,
    charlie.privatePackage,
    emptyPskIndex,
    impl,
  )

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const leaveProposal: Proposal = {
    proposalType: "remove",
    remove: { removed: aliceGroup.privatePath.leafIndex },
  }

  const createLeaveProposalResult = await createProposal(aliceGroup, false, leaveProposal, impl)

  aliceGroup = createLeaveProposalResult.newState

  if (createLeaveProposalResult.message.wireformat !== "mls_private_message")
    throw new Error("Expected private message")

  const bobProcessProposalResult = await processPrivateMessage(
    bobGroup,
    createLeaveProposalResult.message.privateMessage,
    emptyPskIndex,
    impl,
  )

  bobGroup = bobProcessProposalResult.newState

  const charlieProcessProposalResult = await processPrivateMessage(
    charlieGroup,
    createLeaveProposalResult.message.privateMessage,
    emptyPskIndex,
    impl,
  )

  charlieGroup = charlieProcessProposalResult.newState

  //bob commits to alice leaving
  const bobCommitResult = await createCommit(bobGroup, emptyPskIndex, false, [], impl, false)

  bobGroup = bobCommitResult.newState

  if (bobCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const aliceProcessCommitResult = await processPrivateMessage(
    aliceGroup,
    bobCommitResult.commit.privateMessage,
    emptyPskIndex,
    impl,
  )
  aliceGroup = aliceProcessCommitResult.newState

  const charlieProcessCommitResult = await processPrivateMessage(
    charlieGroup,
    bobCommitResult.commit.privateMessage,
    emptyPskIndex,
    impl,
  )
  charlieGroup = charlieProcessCommitResult.newState

  expect(bobGroup.unappliedProposals).toEqual({})
  expect(charlieGroup.unappliedProposals).toEqual({})
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([bobGroup, charlieGroup], impl)
}
