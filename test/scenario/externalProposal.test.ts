import { createGroup, joinGroup } from "../../src/clientState.js"
import { createGroupInfoWithExternalPub } from "../../src/createCommit.js"
import { createCommit } from "../../src/createCommit.js"
import { processPrivateMessage, processPublicMessage } from "../../src/processMessages.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { encodeExternalSender, ExternalSender } from "../../src/externalSender.js"
import { Extension } from "../../src/extension.js"
import { proposeExternal } from "../../src/externalProposal.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"

test.concurrent.each(Object.keys(ciphersuites))(`External Proposal %s`, async (cs) => {
  await externalProposalTest(cs as CiphersuiteName)
})

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
    extensionType: defaultExtensionTypes.external_senders,
    extensionData: encodeExternalSender(externalSender),
  }

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [extension], impl)

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

  // external pub not really necessary here
  const groupInfo = await createGroupInfoWithExternalPub(aliceGroup, [], impl)

  const removeBobProposal: Proposal = {
    proposalType: defaultProposalTypes.remove,
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

  const removeBobCommitResult = await createCommit({
    state: aliceGroup,
    cipherSuite: impl,
  })

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
