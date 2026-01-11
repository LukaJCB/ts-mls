import { generateKeyPackage } from "../src/keyPackage.js"
import { Credential } from "../src/credential.js"
import { Capabilities } from "../src/capabilities.js"
import { defaultLifetime } from "../src/lifetime.js"
import { Extension } from "../src/extension.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../src/crypto/getCiphersuiteImpl.js"
import { defaultCapabilities } from "../src/defaultCapabilities.js"
import { defaultCredentialTypes } from "../src/credentialType.js"

test.concurrent.each(Object.keys(ciphersuites))(`KeyPackage Extension Separation %s`, async (cs) => {
  await keyPackageExtensionSeparationTest(cs as CiphersuiteName)
})

async function keyPackageExtensionSeparationTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  // Create a credential and capabilities for testing
  const credential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("test-user"),
  }

  // Define test extensions
  const keyPackageExtension: Extension = {
    extensionType: 1000,
    extensionData: new TextEncoder().encode("keyPackage-specific-data"),
  }
  const leafNodeExtension: Extension = {
    extensionType: 2000,
    extensionData: new TextEncoder().encode("leafNode-specific-data"),
  }

  // Create capabilities that include our extension types
  const capabilities: Capabilities = {
    ...defaultCapabilities(),
    extensions: [1000, 2000], // Include both extension types in capabilities
  }

  // Generate KeyPackage with separated extensions
  const result = await generateKeyPackage(
    credential,
    capabilities,
    defaultLifetime,
    [keyPackageExtension], // KeyPackage extensions
    impl,
    [leafNodeExtension], // LeafNode extensions
  )
  const publicPackage = result.publicPackage

  // Verify extension separation
  // 1. KeyPackage extensions should be in the KeyPackage TBS
  expect(publicPackage.extensions).toHaveLength(1)
  const keyPackageExt = publicPackage.extensions[0]!
  expect(keyPackageExt.extensionType).toBe(1000)
  expect(keyPackageExt.extensionData).toEqual(new TextEncoder().encode("keyPackage-specific-data"))

  // 2. LeafNode extensions should be in the LeafNode TBS
  expect(publicPackage.leafNode.extensions).toHaveLength(1)
  const leafNodeExt = publicPackage.leafNode.extensions[0]!
  expect(leafNodeExt.extensionType).toBe(2000)
  expect(leafNodeExt.extensionData).toEqual(new TextEncoder().encode("leafNode-specific-data"))

  // 3. Verify extensions are properly separated (no duplication)
  expect(publicPackage.leafNode.extensions).not.toContainEqual(keyPackageExtension)

  // 4. Validate that the capabilities include both extension types
  expect(publicPackage.leafNode.capabilities.extensions).toContain(1000)
  expect(publicPackage.leafNode.capabilities.extensions).toContain(2000)

  // 5. Test backward compatibility: empty leafNodeExtensions parameter
  const backwardCompatResult = await generateKeyPackage(
    credential,
    capabilities,
    defaultLifetime,
    [keyPackageExtension], // KeyPackage extensions
    impl,
    // No leafNodeExtensions parameter (should default to empty array)
  )
  const backwardCompatiblePackage = backwardCompatResult.publicPackage

  // Should only have KeyPackage extensions
  expect(backwardCompatiblePackage.extensions).toHaveLength(1)
  const backwardKeyPackageExt = backwardCompatiblePackage.extensions[0]!
  expect(backwardKeyPackageExt.extensionType).toBe(1000)
  // LeafNode extensions should be empty
  expect(backwardCompatiblePackage.leafNode.extensions).toHaveLength(0)
}
