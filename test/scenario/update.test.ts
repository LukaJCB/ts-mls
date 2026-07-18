import { createGroup, getOwnLeafNode, joinGroup } from "../../src/clientState.js"
import { Credential, credentialEquals } from "../../src/credential.js"
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

import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { generateSignatureKeyPair } from "../../src/signatureKeyPair.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { fastEqual } from "../../src/util/byteArray.js"
import { encode, ValidationError } from "../../src/index.js"
import { capabilitiesEncoder } from "../../src/capabilities.js"
import { varLenTypeEncoder } from "../../src/codec/variableLength.js"
import { extensionEncoder } from "../../src/extension.js"
test.concurrent.each(Object.keys(ciphersuites))(`Update %s`, async (cs) => {
  await update(cs as CiphersuiteName)
})

async function update(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

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

  const addBobCommitResult = await createCommitEnsureNoMutation({
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
    welcome: addBobCommitResult.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const emptyCommitResult = await createCommitEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
  })

  if (emptyCommitResult.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  aliceGroup = emptyCommitResult.newState

  const bobProcessCommitResult = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    message: emptyCommitResult.commit,
  })

  bobGroup = bobProcessCommitResult.newState

  const bobNewSignatureKeys = await generateSignatureKeyPair(impl)

  const bobOldLeafNode = getOwnLeafNode(bobGroup)

  //bob creates a leafNode patch to update his signature key extensions, credential and capabilities
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

  const emptyCommitResult2 = await createCommitEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    leafNodePatch: bobLeafNodePatch,
  })

  bobGroup = emptyCommitResult2.newState

  if (emptyCommitResult2.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const bobNewLeafNode = getOwnLeafNode(bobGroup)

  expect(fastEqual(bobNewLeafNode.hpkePublicKey, bobOldLeafNode.hpkePublicKey)).toBe(false)
  expect(fastEqual(bobNewLeafNode.signaturePublicKey, bobOldLeafNode.signaturePublicKey)).toBe(false)
  expect(fastEqual(bobNewLeafNode.signaturePublicKey, bobNewSignatureKeys.publicKey)).toBe(true)
  expect(fastEqual(bobGroup.signaturePrivateKey, bobNewSignatureKeys.signKey)).toBe(true)
  expect(credentialEquals(bobOldLeafNode.credential, bobNewLeafNode.credential)).toBe(false)
  expect(credentialEquals(bobNewLeafNode.credential, bobLeafNodePatch.credential)).toBe(true)
  expect(
    fastEqual(
      encode(capabilitiesEncoder, bobOldLeafNode.capabilities),
      encode(capabilitiesEncoder, bobNewLeafNode.capabilities),
    ),
  ).toBe(false)
  expect(
    fastEqual(
      encode(capabilitiesEncoder, bobNewLeafNode.capabilities),
      encode(capabilitiesEncoder, bobLeafNodePatch.capabilities),
    ),
  ).toBe(true)
  expect(
    fastEqual(
      encode(varLenTypeEncoder(extensionEncoder), bobOldLeafNode.extensions),
      encode(varLenTypeEncoder(extensionEncoder), bobNewLeafNode.extensions),
    ),
  ).toBe(false)
  expect(
    fastEqual(
      encode(varLenTypeEncoder(extensionEncoder), bobNewLeafNode.extensions),
      encode(varLenTypeEncoder(extensionEncoder), bobLeafNodePatch.extensions),
    ),
  ).toBe(true)

  //if alice doesn't deem bobby a valid successor to bob, the commit is invalid
  const badAuthService = {
    async validateCredential(_credential: Credential, _signaturePublicKey: Uint8Array): Promise<boolean> {
      return true
    },
    async validateSuccessorCredential(_oldCredential: Credential, _newCredential: Credential): Promise<boolean> {
      return false
    },
  }

  await expect(async () =>
    processMessageEnsureNoMutation({
      context: {
        cipherSuite: impl,
        authService: badAuthService,
      },
      state: aliceGroup,
      message: emptyCommitResult2.commit,
    }),
  ).rejects.toThrow(new ValidationError("Could not validate credential as successor to existing one"))

  const aliceProcessCommitResult3 = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    message: emptyCommitResult2.commit,
  })

  aliceGroup = aliceProcessCommitResult3.newState

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}
