import { validateRatchetTree } from "../../src/clientState.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Credential } from "../../src/credential.js"
import { Capabilities } from "../../src/capabilities.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { ValidationError } from "../../src/mlsError.js"
import { RatchetTree } from "../../src/ratchetTree.js"
import { GroupContext } from "../../src/groupContext.js"
import { defaultLifetimeConfig } from "../../src/lifetimeConfig.js"
import { defaultAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))("should reject structurally unsound ratchet tree %s", async (cs) => {
  await testStructuralIntegrity(cs as CiphersuiteName)
})

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
