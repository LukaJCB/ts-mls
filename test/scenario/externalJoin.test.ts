import { createGroup, joinGroup, makePskIndex } from "../../src/clientState"
import { joinGroupExternal } from "../../src/createCommit"
import { createCommit, createGroupInfoWithExternalPub } from "../../src/createCommit"
import { processPublicMessage } from "../../src/processMessages"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, getCiphersuiteImpl, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { ProposalAdd } from "../../src/proposal"
import { checkHpkeKeysMatch } from "../crypto/keyMatch"
import { defaultCapabilities, defaultLifetime, testEveryoneCanMessageEveryone } from "./common"

for (const cs of Object.keys(ciphersuites)) {
  test(`External join ${cs}`, async () => {
    await externalJoin(cs as CiphersuiteName)
  })
}

async function externalJoin(cipherSuite: CiphersuiteName) {
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

  const addBobCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)

  aliceGroup = addBobCommitResult.newState

  let bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const groupInfo = await createGroupInfoWithExternalPub(aliceGroup, impl)

  const charlieJoinGroupCommitResult = await joinGroupExternal(
    groupInfo,
    charlie.publicPackage,
    charlie.privatePackage,
    aliceGroup.ratchetTree,
    false,
    impl,
  )

  let charlieGroup = charlieJoinGroupCommitResult.newState

  aliceGroup = await processPublicMessage(
    aliceGroup,
    charlieJoinGroupCommitResult.publicMessage,
    makePskIndex(aliceGroup, {}),
    impl,
  )

  bobGroup = await processPublicMessage(
    bobGroup,
    charlieJoinGroupCommitResult.publicMessage,
    makePskIndex(bobGroup, {}),
    impl,
  )

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(bobGroup.keySchedule.epochAuthenticator)

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}
