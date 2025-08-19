import { createGroup } from "../../src/clientState"
import { createGroupInfoWithExternalPub } from "../../src/createCommit"
import { Credential } from "../../src/credential"
import { CiphersuiteName, getCiphersuiteImpl, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { defaultLifetime } from "../../src/lifetime"
import { Capabilities } from "../../src/capabilities"
import { Extension, ExtensionType } from "../../src/extension"

for (const cs of Object.keys(ciphersuites)) {
  test(`GroupInfo Custom Extensions ${cs}`, async () => {
    await customExtensionTest(cs as CiphersuiteName)
  })
}

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

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const extensionData = new TextEncoder().encode("custom extension data")

  const customExtension: Extension = {
    extensionType: customExtensionType,
    extensionData: extensionData,
  }

  const gi = await createGroupInfoWithExternalPub(aliceGroup, [customExtension], impl)

  expect(gi.extensions.find((e) => e.extensionType === customExtensionType)).toStrictEqual(customExtension)
}
