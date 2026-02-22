import { createGroup, joinGroup } from "../../src/clientState.js"

import { Credential } from "../../src/credential.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { Capabilities } from "../../src/capabilities.js"
import { GroupContextExtension } from "../../src/extension.js"
import { RequiredCapabilities } from "../../src/requiredCapabilities.js"
import { ValidationError } from "../../src/mlsError.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { createCommitEnsureNoMutation } from "./common.js"

test.concurrent.each(Object.keys(ciphersuites))(`Required Capabilities extension %s`, async (cs) => {
  await requiredCapatabilitiesTest(cs as CiphersuiteName)
})

async function requiredCapatabilitiesTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

  const requiredCapabilities: RequiredCapabilities = {
    extensionTypes: [7, 8],
    credentialTypes: [defaultCredentialTypes.x509, defaultCredentialTypes.basic],
    proposalTypes: [],
  }

  const capabilities: Capabilities = {
    extensions: [7, 8, 9],
    credentials: [defaultCredentialTypes.x509, defaultCredentialTypes.basic],
    proposals: [],
    versions: [protocolVersions.mls10],
    ciphersuites: [ciphersuites[cipherSuite]],
  }

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({
    credential: aliceCredential,
    capabilities,
    cipherSuite: impl,
  })

  const groupId = new TextEncoder().encode("group1")

  const requiredCapabilitiesExtension: GroupContextExtension = {
    extensionType: defaultExtensionTypes.required_capabilities,
    extensionData: requiredCapabilities,
  }

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
    extensions: [requiredCapabilitiesExtension],
  })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({
    credential: bobCredential,
    capabilities,
    cipherSuite: impl,
  })

  const minimalCapabilites: Capabilities = {
    extensions: [],
    credentials: [defaultCredentialTypes.basic],
    proposals: [],
    versions: [protocolVersions.mls10],
    ciphersuites: [ciphersuites[cipherSuite]],
  }

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage({
    credential: charlieCredential,
    capabilities: minimalCapabilites,
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

  const bobGroup = await joinGroup({
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

  const addCharlieProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: charlie.publicPackage,
    },
  }

  await expect(
    createCommitEnsureNoMutation({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: aliceGroup,
      extraProposals: [addCharlieProposal],
    }),
  ).rejects.toThrow(ValidationError)
}
