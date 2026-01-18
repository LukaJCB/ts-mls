import { createGroup, joinGroup } from "../../src/clientState.js"
import { createGroupInfoWithExternalPub } from "../../src/createCommit.js"
import { createCommit } from "../../src/createCommit.js"
import { processPrivateMessage, processPublicMessage } from "../../src/processMessages.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"

import { ExternalSender, externalSenderEncoder } from "../../src/externalSender.js"
import { GroupContextExtension } from "../../src/extension.js"
import { proposeExternal } from "../../src/externalProposal.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { wireformats } from "../../src/wireformat.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`External Proposal %s`, async (cs) => {
  await externalProposalTest(cs as CiphersuiteName)
})

async function externalProposalTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({
    credential: aliceCredential,
    cipherSuite: impl,
  })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({
    credential: bobCredential,
    cipherSuite: impl,
  })

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage({
    credential: charlieCredential,
    cipherSuite: impl,
  })

  const groupId = new TextEncoder().encode("group1")

  const externalSender: ExternalSender = {
    credential: charlieCredential,
    signaturePublicKey: charlie.publicPackage.leafNode.signaturePublicKey,
  }

  const extension: GroupContextExtension = {
    extensionType: defaultExtensionTypes.external_senders,
    extensionData: encode(externalSenderEncoder, externalSender),
  }

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
    extensions: [extension],
  })

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [addBobProposal],
  })

  aliceGroup = addBobCommitResult.newState

  let bobGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: addBobCommitResult.welcome!,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

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

  if (addCharlieProposal.wireformat !== wireformats.mls_public_message) throw new Error("Expected public message")

  const aliceProcessCharlieProposalResult = await processPublicMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      pskIndex: emptyPskIndex,
    },
    state: aliceGroup,
    publicMessage: addCharlieProposal.publicMessage,
  })

  aliceGroup = aliceProcessCharlieProposalResult.newState

  const bobProcessCharlieProposalResult = await processPublicMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      pskIndex: emptyPskIndex,
    },
    state: bobGroup,
    publicMessage: addCharlieProposal.publicMessage,
  })

  bobGroup = bobProcessCharlieProposalResult.newState

  const removeBobCommitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
  })

  aliceGroup = removeBobCommitResult.newState

  if (removeBobCommitResult.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const processRemoveBobResult = await processPrivateMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      pskIndex: emptyPskIndex,
    },
    state: bobGroup,
    privateMessage: removeBobCommitResult.commit.privateMessage,
  })

  bobGroup = processRemoveBobResult.newState

  expect(bobGroup.groupActiveState.kind).toBe("removedFromGroup")

  await checkHpkeKeysMatch(aliceGroup, impl)
}
