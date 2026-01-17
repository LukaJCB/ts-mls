import { createGroup, joinGroupWithExtensions } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { Capabilities } from "../../src/capabilities.js"
import { CustomExtension, makeCustomExtension } from "../../src/extension.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`Custom GroupInfoExtensions %s`, async (cs) => {
  await customGroupInfoExtensionTest(cs as CiphersuiteName)
})

async function customGroupInfoExtensionTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const customExtensionType: number = 92

  const capabilities: Capabilities = {
    extensions: [customExtensionType],
    credentials: [defaultCredentialTypes.basic],
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

  const extensionData = new TextEncoder().encode("custom extension data")

  const customExtension: CustomExtension = makeCustomExtension(customExtensionType, extensionData)

  let aliceGroup = await createGroup(
    groupId,
    alice.publicPackage,
    alice.privatePackage,
    [],
    unsafeTestingAuthenticationService,
    impl,
  )

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, capabilities, defaultLifetime, [], impl)

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
      groupInfoExtensions: [customExtension],
    },
  )

  aliceGroup = addBobCommitResult.newState

  const [bobGroup, groupInfoExtensions] = await joinGroupWithExtensions(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    unsafeTestingAuthenticationService,
    impl,
    aliceGroup.ratchetTree,
  )

  expect(groupInfoExtensions.find((e) => e.extensionType === customExtensionType)).toStrictEqual(customExtension)

  // groupContext should not include the extension
  expect(bobGroup.groupContext.extensions.length).toStrictEqual(0)
}
