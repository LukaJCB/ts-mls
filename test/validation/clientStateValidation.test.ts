import { createGroup, validateRatchetTree } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { generateKeyPackage } from "../../src/keyPackage"
import { Credential } from "../../src/credential"
import { Capabilities } from "../../src/capabilities"
import { CiphersuiteName, getCiphersuiteImpl, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { defaultLifetime } from "../../src/lifetime"
import {
  ProposalAdd,
  ProposalRemove,
  ProposalUpdate,
  ProposalPSK,
  ProposalGroupContextExtensions,
} from "../../src/proposal"
import { ValidationError } from "../../src/mlsError"
import { LeafNodeUpdate } from "../../src/leafNode"
import { RatchetTree } from "../../src/ratchetTree"
import { GroupContext } from "../../src/groupContext"
import { defaultLifetimeConfig } from "../../src/lifetimeConfig"
import { defaultAuthenticationService } from "../../src/authenticationService"
import { emptyPskIndex } from "../../src/pskIndex"
import { defaultClientConfig } from "../../src/clientConfig"

for (const cs of Object.keys(ciphersuites)) {
  const cipherSuite = cs as CiphersuiteName

  describe(`ClientState Validation Tests - ${cipherSuite}`, () => {
    describe("Proposal Validation through createCommit", () => {
      it("should reject commit with update proposal by committer", async () => {
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

        const groupId = new TextEncoder().encode("group1")
        const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

        // Create a proper update leaf node
        const updateLeafNode: LeafNodeUpdate = {
          leafNodeSource: "update",
          signaturePublicKey: alice.publicPackage.leafNode.signaturePublicKey,
          hpkePublicKey: alice.publicPackage.leafNode.hpkePublicKey,
          credential: alice.publicPackage.leafNode.credential,
          capabilities: alice.publicPackage.leafNode.capabilities,
          extensions: alice.publicPackage.leafNode.extensions,
          signature: new Uint8Array(),
        }

        const updateProposal: ProposalUpdate = {
          proposalType: "update",
          update: {
            leafNode: updateLeafNode,
          },
        }

        // This should fail because the committer (alice) is trying to update themselves
        await expect(createCommit(aliceGroup, emptyPskIndex, false, [updateProposal], impl)).rejects.toThrow(
          ValidationError,
        )
      })

      it("should reject commit with remove proposal removing committer", async () => {
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

        const groupId = new TextEncoder().encode("group1")
        const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

        const removeProposal: ProposalRemove = {
          proposalType: "remove",
          remove: {
            removed: 0, // removing committer
          },
        }

        // This should fail because the committer is trying to remove themselves
        await expect(createCommit(aliceGroup, emptyPskIndex, false, [removeProposal], impl)).rejects.toThrow(
          ValidationError,
        )
      })

      it("should reject commit with multiple add proposals containing same keypackage", async () => {
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

        const groupId = new TextEncoder().encode("group1")

        const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
        const bob = await generateKeyPackage(bobCredential, aliceCapabilities, defaultLifetime, [], impl)

        const addProposal: ProposalAdd = {
          proposalType: "add",
          add: {
            keyPackage: bob.publicPackage,
          },
        }

        // Create a group with custom config that treats different keypackages as the same
        const customConfig = {
          ...defaultClientConfig,
          keyPackageEqualityConfig: {
            compareKeyPackages: jest.fn().mockReturnValue(true), // Treat all keypackages as equal
            compareKeyPackageToLeafNode: jest.fn().mockReturnValue(false),
          },
        }

        const aliceGroupWithCustomConfig = await createGroup(
          groupId,
          alice.publicPackage,
          alice.privatePackage,
          [],
          impl,
          customConfig,
        )

        // This should fail because we're adding the "same" keypackage twice
        await expect(
          createCommit(aliceGroupWithCustomConfig, emptyPskIndex, false, [addProposal, addProposal], impl),
        ).rejects.toThrow(ValidationError)
      })

      it("should reject commit with multiple PSK proposals with same PSK ID", async () => {
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

        const groupId = new TextEncoder().encode("group1")
        const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

        const pskId = new Uint8Array([1, 2, 3, 4])
        const pskProposal: ProposalPSK = {
          proposalType: "psk",
          psk: {
            preSharedKeyId: {
              psktype: "external",
              pskId,
              pskNonce: new Uint8Array([5, 6, 7, 8]),
            },
          },
        }

        // This should fail because we're adding the same PSK twice
        await expect(createCommit(aliceGroup, emptyPskIndex, false, [pskProposal, pskProposal], impl)).rejects.toThrow(
          ValidationError,
        )
      })

      it("should reject commit with multiple GroupContextExtensions proposals", async () => {
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

        const groupId = new TextEncoder().encode("group1")
        const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

        const groupContextExtensionsProposal: ProposalGroupContextExtensions = {
          proposalType: "group_context_extensions",
          groupContextExtensions: {
            extensions: [],
          },
        }

        // This should fail because we're adding multiple GroupContextExtensions proposals
        await expect(
          createCommit(
            aliceGroup,
            emptyPskIndex,
            false,
            [groupContextExtensionsProposal, groupContextExtensionsProposal],
            impl,
          ),
        ).rejects.toThrow(ValidationError)
      })
    })

    describe("validateRatchetTree", () => {
      it("should reject structurally unsound ratchet tree", async () => {
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
      })
    })
  })
}
