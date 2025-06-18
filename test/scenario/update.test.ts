import { createGroup, createCommit, joinGroup, processPrivateMessage } from "../../src/clientState"
import { Credential } from "../../src/credential"
import { CiphersuiteName, getCiphersuiteImpl, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { ProposalAdd } from "../../src/proposal"
import { defaultCapabilities, defaultLifetime, testEveryoneCanMessageEveryone } from "./common"

for (const cs of Object.keys(ciphersuites).slice(0, 1)) {
  test(`Update ${cs}`, async () => {
    await update(cs as CiphersuiteName)
  })
}

async function update(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

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

  const emptyCommitResult = await createCommit(aliceGroup, {}, false, [], impl)

  if (emptyCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  aliceGroup = emptyCommitResult.newState

  const bobProcessCommitResult = await processPrivateMessage(
    bobGroup,
    emptyCommitResult.commit.privateMessage,
    {},
    impl,
  )

  bobGroup = bobProcessCommitResult.newState

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}
