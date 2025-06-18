import { createGroup, createCommit, joinGroup, processPrivateMessage } from "../../src/clientState"
import { Credential } from "../../src/credential"
import { CiphersuiteName, getCiphersuiteImpl, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { ProposalAdd } from "../../src/proposal"
import { defaultCapabilities, defaultLifetime, testEveryoneCanMessageEveryone } from "./common"

for (const cs of Object.keys(ciphersuites)) {
  test(`3-party join ${cs}`, async () => {
    await threePartyJoin(cs as CiphersuiteName)
  })
}

async function threePartyJoin(cipherSuite: CiphersuiteName) {
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

  const addBobCommitResult = await createCommit(aliceGroup, {}, false, [addBobProposal], impl)

  aliceGroup = addBobCommitResult.newState

  let bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    [],
    impl,
    aliceGroup.ratchetTree,
  )

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const addCharlieProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: charlie.publicPackage,
    },
  }

  const addCharlieCommitResult = await createCommit(aliceGroup, {}, false, [addCharlieProposal], impl)

  aliceGroup = addCharlieCommitResult.newState

  if (addCharlieCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const res = await processPrivateMessage(bobGroup, addCharlieCommitResult.commit.privateMessage, {}, impl)

  bobGroup = res.newState

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  let charlieGroup = await joinGroup(
    addCharlieCommitResult.welcome!,
    charlie.publicPackage,
    charlie.privatePackage,
    [],
    impl,
    aliceGroup.ratchetTree,
  )

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}
