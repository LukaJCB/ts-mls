import { createGroup, joinGroup, makePskIndex } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { processPrivateMessage } from "../../src/processMessages.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { testEveryoneCanMessageEveryone } from "./common.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
test.concurrent.each(Object.keys(ciphersuites))(`Update %s`, async (cs) => {
  await update(cs as CiphersuiteName)
})

async function update(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

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

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const emptyCommitResult = await createCommit({
    state: aliceGroup,
    cipherSuite: impl,
  })

  if (emptyCommitResult.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  aliceGroup = emptyCommitResult.newState

  const bobProcessCommitResult = await processPrivateMessage(
    bobGroup,
    emptyCommitResult.commit.privateMessage,
    makePskIndex(bobGroup, {}),
    impl,
  )

  bobGroup = bobProcessCommitResult.newState

  const emptyCommitResult3 = await createCommit({
    state: bobGroup,
    cipherSuite: impl,
  })

  if (emptyCommitResult3.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  bobGroup = emptyCommitResult3.newState

  const aliceProcessCommitResult3 = await processPrivateMessage(
    aliceGroup,
    emptyCommitResult3.commit.privateMessage,
    makePskIndex(aliceGroup, {}),
    impl,
  )

  aliceGroup = aliceProcessCommitResult3.newState

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}
