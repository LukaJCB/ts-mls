import { createGroup, joinGroup } from "../../src/clientState.js"
import { createProposal } from "../../src/createMessage.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
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
import { ValidationError } from "@hpke/core"

test.concurrent.each(Object.keys(ciphersuites))(`Add Proposal %s`, async (cs) => {
  await addProposalRoundtrip(cs as CiphersuiteName, true)
  await addProposalRoundtrip(cs as CiphersuiteName, false)
})

async function addProposalRoundtrip(cipherSuite: CiphersuiteName, publicMessage: boolean) {
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

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }

  const charlie = await generateKeyPackage({
    credential: charlieCredential,
    cipherSuite: impl,
  })

  const addCharlieProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: charlie.publicPackage },
  }

  // Bob sends proposal to alice
  const createProposalResult = await createProposal({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    wireAsPublicMessage: publicMessage,
    proposal: addCharlieProposal,
  })

  bobGroup = createProposalResult.newState

  const badAuthService = {
    async validateCredential(_credential: Credential, _signaturePublicKey: Uint8Array): Promise<boolean> {
      return false
    },
    async validateSuccessorCredential(_oldCredential: Credential, _newCredential: Credential): Promise<boolean> {
      return false
    },
  }

  await expect(
    processMessageEnsureNoMutation({
      context: { cipherSuite: impl, authService: badAuthService },
      state: aliceGroup,
      message: createProposalResult.message,
    }),
  ).rejects.toThrow(new ValidationError("Could not validate credential"))

  const processProposalResult = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    message: createProposalResult.message,
  })

  aliceGroup = processProposalResult.newState

  const aliceCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    wireAsPublicMessage: publicMessage,
    ratchetTreeExtension: false,
  })
  aliceGroup = aliceCommit.newState
  if (aliceCommit.commit.wireformat !== preferredWireformat) throw new Error(`Expected ${preferredWireformat} message`)

  const charlieGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    welcome: aliceCommit.welcome!.welcome,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  const bobProcessCommit = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: aliceCommit.commit,
    callback: acceptAll,
  })
  bobGroup = bobProcessCommit.newState

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(charlieGroup.keySchedule.epochAuthenticator)
  expect(bobGroup.unappliedProposals).toEqual({})
  expect(aliceGroup.unappliedProposals).toEqual({})

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}
