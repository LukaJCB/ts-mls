import { createGroup, joinGroup } from "../../src/clientState"
import { createGroupInfoWithExternalPub } from "../../src/createCommit"
import { createCommit } from "../../src/createCommit"
import { processPrivateMessage, processPublicMessage } from "../../src/processMessages"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { generateKeyPackage } from "../../src/keyPackage"
import { ProposalAdd } from "../../src/proposal"
import { checkHpkeKeysMatch } from "../crypto/keyMatch"
import { testEveryoneCanMessageEveryone } from "./common"
import { defaultLifetime } from "../../src/lifetime"
import { defaultCapabilities } from "../../src/defaultCapabilities"
import { encodeExternalSender, ExternalSender } from "../../src/externalSender"
import { Extension } from "../../src/extension"
import { proposeAddExternal } from "../../src/externalProposal"

for (const cs of Object.keys(ciphersuites)) {
  test(`External Add Proposal ${cs}`, async () => {
    await externalAddProposalTest(cs as CiphersuiteName)
  })
}

async function externalAddProposalTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  const externalSender: ExternalSender = {
    credential: charlieCredential,
    signaturePublicKey: charlie.publicPackage.leafNode.signaturePublicKey,
  }

  const extension: Extension = {
    extensionType: "external_senders",
    extensionData: encodeExternalSender(externalSender),
  }

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [extension], impl)

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

  const addCharlieCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [], impl)

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

  let charlieGroup = await joinGroup(
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
