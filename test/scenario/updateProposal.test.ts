import { createGroup, joinGroup } from "../../src/clientState.js"
import { createUpdateProposal } from "../../src/createMessage.js"
import { Credential, credentialEquals } from "../../src/credential.js"
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
import { generateSignatureKeyPair } from "../../src/signatureKeyPair.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { CryptoVerificationError, encode } from "../../src/index.js"
import { capabilitiesEncoder } from "../../src/capabilities.js"
import { extensionEncoder } from "../../src/extension.js"
import { varLenTypeEncoder } from "../../src/codec/variableLength.js"
import { ValidationError } from "@hpke/core"

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

  const bobNewSignatureKeys = await generateSignatureKeyPair(impl)

  // Bob creates a leafNode patch to update his signature key extensions, credential and capabilities
  const bobLeafNodePatch = {
    signatureKeyPair: bobNewSignatureKeys,
    extensions: [
      {
        extensionType: defaultExtensionTypes.application_id,
        extensionData: new Uint8Array(42),
      },
    ],
    credential: {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("bobby"),
    },
    capabilities: { ...defaultCapabilities(), extensions: [0xf000] },
  }

  const bobUpdate = await createUpdateProposal({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    wireAsPublicMessage: publicMessage,
    leafNodePatch: bobLeafNodePatch,
  })
  bobGroup = bobUpdate.newState

  if (bobUpdate.message.wireformat !== preferredWireformat) throw new Error(`Expected ${preferredWireformat} message`)
  expect(fastEqual(bobUpdate.newLeafKeypair.hpkePublicKey, bobOldPub)).toBe(false)

  const bobGroupWithoutUpdatedPrivatePath = {
    ...bobGroup,
  }

  bobGroup = { ...bobGroup, privatePath: updateLeafKey(bobGroup.privatePath, bobUpdate.newLeafKeypair.hpkePrivateKey) }

  // if bob updates his leaf key before someone commits to the proposal, messaging will not work
  const aliceEarlyCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    wireAsPublicMessage: publicMessage,
    ratchetTreeExtension: false,
  })
  await expect(async () =>
    processMessageEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: bobGroup,
      message: aliceEarlyCommit.commit,
      callback: acceptAll,
    }),
  ).rejects.toThrow("OpenError")

  const badAuthService = {
    async validateCredential(_credential: Credential, _signaturePublicKey: Uint8Array): Promise<boolean> {
      return true
    },
    async validateSuccessorCredential(_oldCredential: Credential, _newCredential: Credential): Promise<boolean> {
      return false
    },
  }

  //if alice doesn't deem bobby a valid successor to bob, the proposal is invalid
  await expect(async () =>
    processMessageEnsureNoMutation({
      context: {
        cipherSuite: impl,
        authService: badAuthService,
      },
      state: aliceGroup,
      message: bobUpdate.message,
    }),
  ).rejects.toThrow(new ValidationError("Could not validate credential as successor to existing one"))

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

  //processing the message without updating the private key will result in error
  await expect(async () =>
    processMessageEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: bobGroupWithoutUpdatedPrivatePath,
      message: aliceCommit.commit,
      callback: acceptAll,
    }),
  ).rejects.toThrow("OpenError")

  const bobProcessCommit = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    message: aliceCommit.commit,
    callback: acceptAll,
  })
  bobGroup = bobProcessCommit.newState

  //messaging should fail when not updating the private signature key
  await expect(async () => testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)).rejects.toThrow(
    new CryptoVerificationError("Signature invalid"),
  )

  // bob updates his signature key to the new one
  bobGroup = { ...bobGroup, signaturePrivateKey: bobNewSignatureKeys.signKey }

  const bobLeafAfter = getOwnLeafNode(bobGroup)
  expect(fastEqual(bobLeafAfter.hpkePublicKey, bobUpdate.newLeafKeypair.hpkePublicKey)).toBe(true)
  expect(fastEqual(bobLeafAfter.signaturePublicKey, bobNewSignatureKeys.publicKey)).toBe(true)
  expect(credentialEquals(bobLeafAfter.credential, bobLeafNodePatch.credential)).toBe(true)
  expect(
    fastEqual(
      encode(capabilitiesEncoder, bobLeafAfter.capabilities),
      encode(capabilitiesEncoder, bobLeafNodePatch.capabilities),
    ),
  ).toBe(true)
  expect(
    fastEqual(
      encode(varLenTypeEncoder(extensionEncoder), bobLeafAfter.extensions),
      encode(varLenTypeEncoder(extensionEncoder), bobLeafNodePatch.extensions),
    ),
  ).toBe(true)

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(bobGroup.unappliedProposals).toEqual({})
  expect(aliceGroup.unappliedProposals).toEqual({})

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)

  //both commit again
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
