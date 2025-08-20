import { ClientState, createGroup, joinGroup, makePskIndex } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { emptyPskIndex } from "../../src/pskIndex"
import { joinGroupFromReinit, reinitCreateNewGroup, reinitGroup } from "../../src/resumption"
import { Credential } from "../../src/credential"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { generateKeyPackage } from "../../src/keyPackage"
import { ProposalAdd } from "../../src/proposal"
import { defaultLifetime } from "../../src/lifetime"
import { defaultCapabilities } from "../../src/defaultCapabilities"
import { processMessage } from "../../src/processMessages"
import { acceptAll } from "../../src/IncomingMessageAction"

import { ProtocolVersionName } from "../../src/protocolVersion"
import { ValidationError } from "../../src/mlsError"

for (const cs of Object.keys(ciphersuites)) {
  test(`Reinit Validation ${cs}`, async () => {
    await reinitValidation(cs as CiphersuiteName)
  })
}

async function reinitValidation(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const commitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)

  aliceGroup = commitResult.newState

  let bobGroup = await joinGroup(
    commitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  const bobCommitResult = await createCommit(bobGroup, emptyPskIndex, false, [], impl)

  bobGroup = bobCommitResult.newState

  if (bobCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const processBobCommitResult = await processMessage(
    bobCommitResult.commit,
    aliceGroup,
    emptyPskIndex,
    acceptAll,
    impl,
  )

  aliceGroup = processBobCommitResult.newState

  const bobNewKeyPackage = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const aliceNewKeyPackage = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const newGroupId = new TextEncoder().encode("new-group1")

  const reinitCommitResult = await reinitGroup(aliceGroup, newGroupId, "mls10", cipherSuite, [], impl)

  aliceGroup = reinitCommitResult.newState

  if (reinitCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const processReinitResult = await processMessage(
    reinitCommitResult.commit,
    bobGroup,
    makePskIndex(bobGroup, {}),
    acceptAll,
    impl,
  )

  bobGroup = processReinitResult.newState

  expect(bobGroup.groupActiveState.kind).toBe("suspendedPendingReinit")
  expect(aliceGroup.groupActiveState.kind).toBe("suspendedPendingReinit")

  const resumeGroupResult = await reinitCreateNewGroup(
    aliceGroup,
    aliceNewKeyPackage.publicPackage,
    aliceNewKeyPackage.privatePackage,
    [bobNewKeyPackage.publicPackage],
    newGroupId,
    cipherSuite,
    [],
  )

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
    joinGroupFromReinit(
      bobGroupIdChanged,
      resumeGroupResult.welcome!,
      bobNewKeyPackage.publicPackage,
      bobNewKeyPackage.privatePackage,
      aliceGroup.ratchetTree,
    ),
  ).rejects.toThrow(ValidationError)

  const bobVersionChanged: ClientState = {
    ...bobGroup,
    groupActiveState: {
      kind: "suspendedPendingReinit",
      reinit: { ...reinit!, version: "mls2" as ProtocolVersionName },
    },
  }

  await expect(
    joinGroupFromReinit(
      bobVersionChanged,
      resumeGroupResult.welcome!,
      bobNewKeyPackage.publicPackage,
      bobNewKeyPackage.privatePackage,
      aliceGroup.ratchetTree,
    ),
  ).rejects.toThrow(ValidationError)

  const bobExtensionsChanged: ClientState = {
    ...bobGroup,
    groupActiveState: {
      kind: "suspendedPendingReinit",
      reinit: { ...reinit!, extensions: [{ extensionType: 17, extensionData: new Uint8Array([1]) }] },
    },
  }

  await expect(
    joinGroupFromReinit(
      bobExtensionsChanged,
      resumeGroupResult.welcome!,
      bobNewKeyPackage.publicPackage,
      bobNewKeyPackage.privatePackage,
      aliceGroup.ratchetTree,
    ),
  ).rejects.toThrow(ValidationError)
}
