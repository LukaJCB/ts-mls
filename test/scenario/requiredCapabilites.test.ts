import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { Capabilities } from "../../src/capabilities.js"
import { GroupContextExtension } from "../../src/extension.js"
import { RequiredCapabilities, requiredCapabilitiesEncoder } from "../../src/requiredCapabilities.js"
import { ValidationError } from "../../src/mlsError.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`Required Capabilities extension %s`, async (cs) => {
  await requiredCapatabilitiesTest(cs as CiphersuiteName)
})

async function requiredCapatabilitiesTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

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
  const alice = await generateKeyPackage(aliceCredential, capabilities, defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  const requiredCapabilitiesExtension: GroupContextExtension = {
    extensionType: defaultExtensionTypes.required_capabilities,
    extensionData: encode(requiredCapabilitiesEncoder, requiredCapabilities),
  }

  let aliceGroup = await createGroup(
    groupId,
    alice.publicPackage,
    alice.privatePackage,
    [requiredCapabilitiesExtension],
    unsafeTestingAuthenticationService,
    impl,
  )

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, capabilities, defaultLifetime, [], impl)

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
  const charlie = await generateKeyPackage(charlieCredential, minimalCapabilites, defaultLifetime, [], impl)

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
      authService: unsafeTestingAuthenticationService,
    },
    {
      extraProposals: [addBobProposal],
    },
  )

  aliceGroup = addBobCommitResult.newState

  const bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    unsafeTestingAuthenticationService,
    impl,
    aliceGroup.ratchetTree,
  )

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const addCharlieProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: charlie.publicPackage,
    },
  }

  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      {
        extraProposals: [addCharlieProposal],
      },
    ),
  ).rejects.toThrow(ValidationError)
}
