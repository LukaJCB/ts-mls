import { createGroup, joinGroup } from "../../src/clientState.js"
import { createGroupInfoWithExternalPub } from "../../src/createCommit.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { ExternalSender } from "../../src/externalSender.js"
import { GroupContextExtension } from "../../src/extension.js"
import { proposeExternal } from "../../src/externalProposal.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { createCommitEnsureNoMutation, processMessageEnsureNoMutation } from "./common.js"

test.concurrent.each(Object.keys(ciphersuites))(`External proposal with multiple senders %s`, async (cs) => {
  await externalProposalMultipleSendersTest(cs as CiphersuiteName)
})

async function externalProposalMultipleSendersTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })

  // Two external signers; we want to send a proposal authored by the second one.
  const ext0Credential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("external-0"),
  }
  const ext0 = await generateKeyPackage({ credential: ext0Credential, cipherSuite: impl })

  const ext1Credential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("external-1"),
  }
  const ext1 = await generateKeyPackage({ credential: ext1Credential, cipherSuite: impl })

  const externalSenders: ExternalSender[] = [
    { credential: ext0Credential, signaturePublicKey: ext0.publicPackage.leafNode.signaturePublicKey },
    { credential: ext1Credential, signaturePublicKey: ext1.publicPackage.leafNode.signaturePublicKey },
  ]

  const extension: GroupContextExtension = {
    extensionType: defaultExtensionTypes.external_senders,
    extensionData: externalSenders,
  }

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId: new TextEncoder().encode("group1"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
    extensions: [extension],
  })

  const addBob: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: bob.publicPackage },
  }
  const addBobCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [addBob],
    ratchetTreeExtension: true,
  })
  aliceGroup = addBobCommit.newState

  let bobGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    welcome: addBobCommit.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
  })

  const groupInfo = await createGroupInfoWithExternalPub(aliceGroup, [], impl)

  const proposal: Proposal = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: bob.publicPackage },
  }

  // Author the external proposal as the *second* external signer.
  const externalProposalMsg = await proposeExternal(
    groupInfo,
    proposal,
    ext1.publicPackage.leafNode.signaturePublicKey,
    ext1.privatePackage.signaturePrivateKey,
    impl,
  )
  if (externalProposalMsg.wireformat !== wireformats.mls_public_message) throw new Error("Expected public message")

  // Both members must validate the signature, which requires senderFromExtension
  // to look up index 1 inside extensionData.
  const aliceProcess = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    message: externalProposalMsg,
  })
  aliceGroup = aliceProcess.newState

  const bobProcess = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: externalProposalMsg,
  })
  bobGroup = bobProcess.newState

  expect(Object.keys(aliceGroup.unappliedProposals).length).toBe(1)
  expect(Object.keys(bobGroup.unappliedProposals).length).toBe(1)
}
