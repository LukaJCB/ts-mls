import { createGroup, joinGroup } from "../../src/clientState"
import { createGroupInfoWithExternalPub } from "../../src/createCommit"
import { createCommit } from "../../src/createCommit"
import { processPrivateMessage, processPublicMessage } from "../../src/processMessages"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, getCiphersuiteImpl, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { Proposal, ProposalAdd } from "../../src/proposal"
import { checkHpkeKeysMatch } from "../crypto/keyMatch"
import { defaultLifetime } from "../../src/lifetime"
import { defaultCapabilities } from "../../src/defaultCapabilities"
import { encodeExternalSender, ExternalSender } from "../../src/externalSender"
import { Extension } from "../../src/extension"
import { proposeExternal } from "../../src/externalProposal"

for (const cs of Object.keys(ciphersuites)) {
  test(`External Proposal ${cs}`, async () => {
    await externalProposalTest(cs as CiphersuiteName)
  })
}

async function externalProposalTest(cipherSuite: CiphersuiteName) {
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

  const removeBobProposal: Proposal = {
    proposalType: "remove",
    remove: {
      removed: 1,
    },
  }

  const addCharlieProposal = await proposeExternal(
    groupInfo,
    removeBobProposal,
    charlie.publicPackage.leafNode.signaturePublicKey,
    charlie.privatePackage.signaturePrivateKey,
    impl,
  )

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

  const removeBobCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [], impl)

  aliceGroup = removeBobCommitResult.newState

  if (removeBobCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const processRemoveBobResult = await processPrivateMessage(
    bobGroup,
    removeBobCommitResult.commit.privateMessage,
    emptyPskIndex,
    impl,
  )

  bobGroup = processRemoveBobResult.newState

  expect(bobGroup.groupActiveState.kind).toBe("removedFromGroup")

  await checkHpkeKeysMatch(aliceGroup, impl)
}
