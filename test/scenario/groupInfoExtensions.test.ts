import { createGroup } from "../../src/clientState.js"
import { createGroupInfoWithExternalPub } from "../../src/createCommit.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { Capabilities } from "../../src/capabilities.js"
import { Extension, ExtensionType } from "../../src/extension.js"

test.concurrent.each(Object.keys(ciphersuites))(`GroupInfo Custom Extensions %s`, async (cs) => {
  await customExtensionTest(cs as CiphersuiteName)
})

async function customExtensionTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const customExtensionType: ExtensionType = 7

  const capabilities: Capabilities = {
    extensions: [customExtensionType],
    credentials: ["basic"],
    proposals: [],
    versions: ["mls10"],
    ciphersuites: [cipherSuite],
  }

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, capabilities, defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const extensionData = new TextEncoder().encode("custom extension data")

  const customExtension: Extension = {
    extensionType: customExtensionType,
    extensionData: extensionData,
  }

  const gi = await createGroupInfoWithExternalPub(aliceGroup, [customExtension], impl)

  expect(gi.extensions.find((e) => e.extensionType === customExtensionType)).toStrictEqual(customExtension)
}
