import { ciphersuites, CiphersuiteName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { defaultLifetimeConfig } from "../../src/lifetimeConfig.js"
import { RatchetTree } from "../../src/ratchetTree.js"
import { GroupContext } from "../../src/groupContext.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { nodeTypes } from "../../src/nodeType.js"
import { ValidationError } from "../../src/mlsError.js"
import { validateRatchetTree } from "../../src/validation.js"

describe("Ratchet tree unmerged leaf bounds", () => {
  test.concurrent.each(Object.keys(ciphersuites))("rejects out-of-range unmerged leaves (%s)", async (cs) => {
    const impl = await getCiphersuiteImpl(cs as CiphersuiteName)
    const credential = (identity: string) => ({
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode(identity),
    })
    const [alice, bob] = await Promise.all([
      generateKeyPackage({ credential: credential("alice"), cipherSuite: impl }),
      generateKeyPackage({ credential: credential("bob"), cipherSuite: impl }),
    ])

    const tree: RatchetTree = [
      { nodeType: nodeTypes.leaf, leaf: alice.publicPackage.leafNode },
      {
        nodeType: nodeTypes.parent,
        parent: {
          unmergedLeaves: [999999],
          parentHash: new Uint8Array(),
          hpkePublicKey: new Uint8Array([1]),
        },
      },
      { nodeType: nodeTypes.leaf, leaf: bob.publicPackage.leafNode },
    ]
    const groupContext: GroupContext = {
      version: protocolVersions.mls10,
      cipherSuite: ciphersuites[cs as CiphersuiteName],
      epoch: 0n,
      treeHash: new Uint8Array(),
      groupId: new Uint8Array(),
      extensions: [],
      confirmedTranscriptHash: new Uint8Array(),
    }

    const error = await validateRatchetTree(
      tree,
      groupContext,
      defaultLifetimeConfig,
      unsafeTestingAuthenticationService,
      new Uint8Array(),
      impl,
    )

    expect(error).toEqual(new ValidationError("Unmerged leaf index out of range"))
  })
})
