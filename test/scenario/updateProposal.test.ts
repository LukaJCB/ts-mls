import { createGroup, joinGroup } from "../../src/clientState.js"
import { createUpdateProposal } from "../../src/createMessage.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { updateLeafKey } from "../../src/privateKeyPath.js"
import { getOwnLeafNode } from "../../src/clientState.js"
import { fastEqual } from "../../src/util/byteArray.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"
import { acceptAll } from "../../src/incomingMessageAction.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`Update Proposal %s`, async (cs) => {
  await updateProposalRoundtrip(cs as CiphersuiteName, true)
  await updateProposalRoundtrip(cs as CiphersuiteName, false)
})

async function updateProposalRoundtrip(cipherSuite: CiphersuiteName, publicMessage: boolean) {
  const impl = await getCiphersuiteImpl(cipherSuite)
  const preferredWireformat = publicMessage ? wireformats.mls_public_message : wireformats.mls_private_message

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId: new TextEncoder().encode("group1"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })

  const addBob: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: bob.publicPackage },
  }

  const addBobCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    wireAsPublicMessage: publicMessage,
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
  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const bobOldPub = getOwnLeafNode(bobGroup).hpkePublicKey

  const bobUpdate = await createUpdateProposal({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    wireAsPublicMessage: publicMessage,
  })
  bobGroup = bobUpdate.newState

  if (bobUpdate.message.wireformat !== preferredWireformat) throw new Error(`Expected ${preferredWireformat} message`)
  expect(fastEqual(bobUpdate.newLeafKeypair.hpkePublicKey, bobOldPub)).toBe(false)

  const aliceProcessProposal = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    message: bobUpdate.message,
    callback: acceptAll,
  })
  aliceGroup = aliceProcessProposal.newState

  const aliceCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    wireAsPublicMessage: publicMessage,
    ratchetTreeExtension: false,
  })
  aliceGroup = aliceCommit.newState
  if (aliceCommit.commit.wireformat !== preferredWireformat) throw new Error(`Expected ${preferredWireformat} message`)

  const bobProcessCommit = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: aliceCommit.commit,
    callback: acceptAll,
  })
  bobGroup = bobProcessCommit.newState

  const bobLeafAfter = getOwnLeafNode(bobGroup)
  expect(fastEqual(bobLeafAfter.hpkePublicKey, bobUpdate.newLeafKeypair.hpkePublicKey)).toBe(true)

  bobGroup = { ...bobGroup, privatePath: updateLeafKey(bobGroup.privatePath, bobUpdate.newLeafKeypair.hpkePrivateKey) }

  const aliceCommit2 = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    wireAsPublicMessage: publicMessage,
    ratchetTreeExtension: false,
  })
  aliceGroup = aliceCommit2.newState
  if (aliceCommit2.commit.wireformat !== preferredWireformat) throw new Error(`Expected ${preferredWireformat} message`)

  const bobProcessCommit2 = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: aliceCommit2.commit,
    callback: acceptAll,
  })
  bobGroup = bobProcessCommit2.newState

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(bobGroup.unappliedProposals).toEqual({})
  expect(aliceGroup.unappliedProposals).toEqual({})

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}
