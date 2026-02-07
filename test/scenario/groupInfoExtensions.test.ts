import { createGroup } from "../../src/clientState.js"
import { createGroupInfoWithExternalPub } from "../../src/createCommit.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Capabilities } from "../../src/capabilities.js"
import { CustomExtension, makeCustomExtension } from "../../src/extension.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`GroupInfo Custom Extensions %s`, async (cs) => {
  await customExtensionTest(cs as CiphersuiteName)
})

async function customExtensionTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

  const customExtensionType: number = 71

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
  const alice = await generateKeyPackage({
    credential: aliceCredential,
    capabilities,
    cipherSuite: impl,
  })

  const groupId = new TextEncoder().encode("group1")

  const aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const extensionData = new TextEncoder().encode("custom extension data")

  const customExtension: CustomExtension = makeCustomExtension({
    extensionType: customExtensionType,
    extensionData,
  })

  const gi = await createGroupInfoWithExternalPub(aliceGroup, [customExtension], impl)

  expect(gi.extensions.find((e) => e.extensionType === customExtensionType)).toStrictEqual(customExtension)
}
