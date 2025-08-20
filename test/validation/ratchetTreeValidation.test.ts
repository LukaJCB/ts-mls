import { validateRatchetTree } from "../../src/clientState"
import { generateKeyPackage } from "../../src/keyPackage"
import { Credential } from "../../src/credential"
import { Capabilities } from "../../src/capabilities"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { defaultLifetime } from "../../src/lifetime"
import { ValidationError } from "../../src/mlsError"
import { RatchetTree } from "../../src/ratchetTree"
import { GroupContext } from "../../src/groupContext"
import { defaultLifetimeConfig } from "../../src/lifetimeConfig"
import { defaultAuthenticationService } from "../../src/authenticationService"

for (const cs of Object.keys(ciphersuites)) {
  test("should reject structurally unsound ratchet tree", async () => {
    await testStructuralIntegrity(cs as CiphersuiteName)
  })
}
async function testStructuralIntegrity(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))
  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const aliceCapabilities: Capabilities = {
    extensions: [],
    credentials: ["basic"],
    proposals: [],
    versions: ["mls10"],
    ciphersuites: [cipherSuite],
  }
  const alice = await generateKeyPackage(aliceCredential, aliceCapabilities, defaultLifetime, [], impl)

  const validLeafNode = alice.publicPackage.leafNode
  // Make the first node a parent node, which is invalid for a leaf position
  const invalidTree: RatchetTree = [
    {
      nodeType: "parent",
      parent: {
        unmergedLeaves: [],
        parentHash: new Uint8Array(),
        hpkePublicKey: new Uint8Array(),
      },
    },
    { nodeType: "leaf", leaf: validLeafNode },
    { nodeType: "leaf", leaf: validLeafNode },
  ]

  const groupContext: GroupContext = {
    version: "mls10",
    cipherSuite: cipherSuite,
    epoch: 0n,
    treeHash: new Uint8Array(),
    groupId: new Uint8Array(),
    extensions: [],
    confirmedTranscriptHash: new Uint8Array(),
  }

  const error = await validateRatchetTree(
    invalidTree,
    groupContext,
    defaultLifetimeConfig,
    defaultAuthenticationService,
    new Uint8Array(),
    impl,
  )

  expect(error).toBeInstanceOf(ValidationError)
  expect(error?.message).toBe("Received Ratchet Tree is not structurally sound")
}
