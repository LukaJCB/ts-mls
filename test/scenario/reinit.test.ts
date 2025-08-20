import { createGroup, joinGroup, makePskIndex } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { processPrivateMessage } from "../../src/processMessages"
import { emptyPskIndex } from "../../src/pskIndex"
import { joinGroupFromReinit, reinitCreateNewGroup, reinitGroup } from "../../src/resumption"
import { Credential } from "../../src/credential"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { generateKeyPackage } from "../../src/keyPackage"
import { ProposalAdd } from "../../src/proposal"
import { checkHpkeKeysMatch } from "../crypto/keyMatch"
import { getRandomElement, testEveryoneCanMessageEveryone } from "./common"
import { defaultLifetime } from "../../src/lifetime"
import { defaultCapabilities } from "../../src/defaultCapabilities"
import { UsageError } from "../../src/mlsError"

for (const cs of Object.keys(ciphersuites)) {
  test(`Reinit ${cs}`, async () => {
    await reinit(cs as CiphersuiteName)
  })
}

async function reinit(cipherSuite: CiphersuiteName) {
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

  const newCiphersuite = getRandomElement(Object.keys(ciphersuites)) as CiphersuiteName

  const newGroupId = new TextEncoder().encode("new-group1")

  const reinitCommitResult = await reinitGroup(aliceGroup, newGroupId, "mls10", newCiphersuite, [], impl)

  aliceGroup = reinitCommitResult.newState

  if (reinitCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const processReinitResult = await processPrivateMessage(
    bobGroup,
    reinitCommitResult.commit.privateMessage,
    makePskIndex(bobGroup, {}),
    impl,
  )

  bobGroup = processReinitResult.newState

  expect(bobGroup.groupActiveState.kind).toBe("suspendedPendingReinit")
  expect(aliceGroup.groupActiveState.kind).toBe("suspendedPendingReinit")

  //creating a message will fail now
  await expect(createCommit(aliceGroup, emptyPskIndex, false, [], impl)).rejects.toThrow(UsageError)

  const newImpl = await getCiphersuiteImpl(getCiphersuiteFromName(newCiphersuite))

  const bobNewKeyPackage = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], newImpl)

  const aliceNewKeyPackage = await generateKeyPackage(
    aliceCredential,
    defaultCapabilities(),
    defaultLifetime,
    [],
    newImpl,
  )

  const resumeGroupResult = await reinitCreateNewGroup(
    aliceGroup,
    aliceNewKeyPackage.publicPackage,
    aliceNewKeyPackage.privatePackage,
    [bobNewKeyPackage.publicPackage],
    newGroupId,
    newCiphersuite,
    [],
  )

  aliceGroup = resumeGroupResult.newState

  bobGroup = await joinGroupFromReinit(
    bobGroup,
    resumeGroupResult.welcome!,
    bobNewKeyPackage.publicPackage,
    bobNewKeyPackage.privatePackage,
    aliceGroup.ratchetTree,
  )

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], newImpl)
  await checkHpkeKeysMatch(aliceGroup, newImpl)
  await checkHpkeKeysMatch(bobGroup, newImpl)
}
