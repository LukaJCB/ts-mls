import { generateKeyPackage } from "../src/keyPackage.js"
import { Credential } from "../src/credential.js"
import { CustomExtension, makeCustomExtension } from "../src/extension.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../src/crypto/getCiphersuiteImpl.js"
import { defaultCredentialTypes } from "../src/defaultCredentialType.js"

test.concurrent.each(Object.keys(ciphersuites))(`KeyPackage Extension Separation %s`, async (cs) => {
  await keyPackageExtensionSeparationTest(cs as CiphersuiteName)
})

async function keyPackageExtensionSeparationTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const credential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("test-user"),
  }

  const keyPackageExtension: CustomExtension = makeCustomExtension(
    1000,
    new TextEncoder().encode("keyPackage-specific-data"),
  )
  const leafNodeExtension: CustomExtension = makeCustomExtension(
    2000,
    new TextEncoder().encode("leafNode-specific-data"),
  )

  const result = await generateKeyPackage({
    credential,
    extensions: [keyPackageExtension],
    cipherSuite: impl,
    leafNodeExtensions: [leafNodeExtension],
  })
  const publicPackage = result.publicPackage

  expect(publicPackage.extensions).toHaveLength(1)
  const keyPackageExt = publicPackage.extensions[0]!
  expect(keyPackageExt.extensionType).toBe(1000)
  expect(keyPackageExt.extensionData).toEqual(new TextEncoder().encode("keyPackage-specific-data"))

  expect(publicPackage.leafNode.extensions).toHaveLength(1)
  const leafNodeExt = publicPackage.leafNode.extensions[0]!
  expect(leafNodeExt.extensionType).toBe(2000)
  expect(leafNodeExt.extensionData).toEqual(new TextEncoder().encode("leafNode-specific-data"))

  expect(publicPackage.leafNode.extensions).not.toContainEqual(keyPackageExtension)

  const backwardCompatResult = await generateKeyPackage({
    credential,

    extensions: [keyPackageExtension],
    cipherSuite: impl,
  })
  const backwardCompatiblePackage = backwardCompatResult.publicPackage

  expect(backwardCompatiblePackage.extensions).toHaveLength(1)
  const backwardKeyPackageExt = backwardCompatiblePackage.extensions[0]!
  expect(backwardKeyPackageExt.extensionType).toBe(1000)

  expect(backwardCompatiblePackage.leafNode.extensions).toHaveLength(0)
}
