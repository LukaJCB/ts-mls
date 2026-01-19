import { ClientState, createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { joinGroupFromReinit, reinitCreateNewGroup, reinitGroup } from "../../src/resumption.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"

import { processMessage } from "../../src/processMessages.js"
import { acceptAll } from "../../src/incomingMessageAction.js"

import { ProtocolVersionValue } from "../../src/protocolVersion.js"
import { ValidationError } from "../../src/mlsError.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { wireformats } from "../../src/wireformat.js"
import { makeCustomExtension } from "../../src/extension.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`Reinit Validation %s`, async (cs) => {
  await reinitValidation(cs as CiphersuiteName)
})

async function reinitValidation(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({
    credential: aliceCredential,
    cipherSuite: impl,
  })

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({
    credential: bobCredential,
    cipherSuite: impl,
  })

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const commitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [addBobProposal],
  })

  aliceGroup = commitResult.newState

  let bobGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    welcome: commitResult.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  const bobCommitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
  })

  bobGroup = bobCommitResult.newState

  if (bobCommitResult.commit.wireformat !== wireformats.mls_private_message) throw new Error("Expected private message")

  const processBobCommitResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    message: bobCommitResult.commit,
    callback: acceptAll,
  })

  aliceGroup = processBobCommitResult.newState

  const bobNewKeyPackage = await generateKeyPackage({
    credential: bobCredential,
    cipherSuite: impl,
  })

  const aliceNewKeyPackage = await generateKeyPackage({
    credential: aliceCredential,
    cipherSuite: impl,
  })

  const newGroupId = new TextEncoder().encode("new-group1")

  const reinitCommitResult = await reinitGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    groupId: newGroupId,
    version: "mls10",
    cipherSuite,
  })

  aliceGroup = reinitCommitResult.newState

  if (reinitCommitResult.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const processReinitResult = await processMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    message: reinitCommitResult.commit,
    callback: acceptAll,
  })

  bobGroup = processReinitResult.newState

  expect(bobGroup.groupActiveState.kind).toBe("suspendedPendingReinit")
  expect(aliceGroup.groupActiveState.kind).toBe("suspendedPendingReinit")

  const resumeGroupResult = await reinitCreateNewGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    keyPackage: aliceNewKeyPackage.publicPackage,
    privateKeyPackage: aliceNewKeyPackage.privatePackage,
    memberKeyPackages: [bobNewKeyPackage.publicPackage],
    groupId: newGroupId,
    cipherSuite,
  })

  aliceGroup = resumeGroupResult.newState

  const reinit =
    bobGroup.groupActiveState.kind === "suspendedPendingReinit" ? bobGroup.groupActiveState.reinit : undefined

  const bobGroupIdChanged: ClientState = {
    ...bobGroup,
    groupActiveState: {
      kind: "suspendedPendingReinit",
      reinit: { ...reinit!, groupId: new TextEncoder().encode("group-bad") },
    },
  }

  await expect(
    joinGroupFromReinit({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      suspendedState: bobGroupIdChanged,
      welcome: resumeGroupResult.welcome!.welcome,
      keyPackage: bobNewKeyPackage.publicPackage,
      privateKeyPackage: bobNewKeyPackage.privatePackage,
      ratchetTree: aliceGroup.ratchetTree,
    }),
  ).rejects.toThrow(ValidationError)

  const bobVersionChanged: ClientState = {
    ...bobGroup,
    groupActiveState: {
      kind: "suspendedPendingReinit",
      reinit: { ...reinit!, version: 0xffff as ProtocolVersionValue },
    },
  }

  await expect(
    joinGroupFromReinit({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      suspendedState: bobVersionChanged,
      welcome: resumeGroupResult.welcome!.welcome,
      keyPackage: bobNewKeyPackage.publicPackage,
      privateKeyPackage: bobNewKeyPackage.privatePackage,
      ratchetTree: aliceGroup.ratchetTree,
    }),
  ).rejects.toThrow(ValidationError)

  const bobExtensionsChanged: ClientState = {
    ...bobGroup,
    groupActiveState: {
      kind: "suspendedPendingReinit",
      reinit: {
        ...reinit!,
        extensions: [makeCustomExtension({ extensionType: 17, extensionData: new Uint8Array([1]) })],
      },
    },
  }

  await expect(
    joinGroupFromReinit({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      suspendedState: bobExtensionsChanged,
      welcome: resumeGroupResult.welcome!.welcome,
      keyPackage: bobNewKeyPackage.publicPackage,
      privateKeyPackage: bobNewKeyPackage.privatePackage,
      ratchetTree: aliceGroup.ratchetTree,
    }),
  ).rejects.toThrow(ValidationError)
}
