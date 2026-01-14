import { ClientState, createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit, createGroupInfoWithExternalPub } from "../../src/createCommit.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential, isDefaultCredential } from "../../src/credential.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd, ProposalRemove } from "../../src/proposal.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { CodecError, ValidationError } from "../../src/mlsError.js"
import { requiredCapabilitiesEncoder } from "../../src/requiredCapabilities.js"
import { externalSenderEncoder } from "../../src/externalSender.js"
import { AuthenticationService } from "../../src/authenticationService.js"
import { constantTimeEqual } from "../../src/util/constantTimeCompare.js"
import { createCustomCredential } from "../../src/customCredential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { Extension } from "../../src/extension.js"
import { LeafNode } from "../../src/leafNode.js"
import { proposeExternal } from "../../src/index.js"
import { Capabilities } from "../../src/capabilities.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { leafNodeSources } from "../../src/leafNodeSource.js"
import { pskTypes } from "../../src/presharedkey.js"
import { encode } from "../../src/codec/tlsEncoder.js"

describe("Proposal Validation", () => {
  const suites = Object.keys(ciphersuites).slice(0, 1)

  test.concurrent.each(suites)("can't remove same leaf node twice %s", async (cs) => {
    const { impl, aliceGroup, bobGroup } = await setupThreeMembers(cs as CiphersuiteName)

    const removeBobProposal: ProposalRemove = {
      proposalType: defaultProposalTypes.remove,
      remove: { removed: bobGroup.privatePath.leafIndex },
    }

    const removeBobProposal2: ProposalRemove = {
      proposalType: defaultProposalTypes.remove,
      remove: { removed: bobGroup.privatePath.leafIndex },
    }

    await expect(
      createCommit(
        { state: aliceGroup, cipherSuite: impl },
        { extraProposals: [removeBobProposal, removeBobProposal2] },
      ),
    ).rejects.toThrow(
      new ValidationError("Commit cannot contain multiple update and/or remove proposals that apply to the same leaf"),
    )
  })

  test.concurrent.each(suites)("can't add someone already in the group %s", async (cs) => {
    const { impl, aliceGroup, addBobProposal } = await setupThreeMembers(cs as CiphersuiteName)

    await expect(
      createCommit({ state: aliceGroup, cipherSuite: impl }, { extraProposals: [addBobProposal] }),
    ).rejects.toThrow(new ValidationError("Commit cannot contain an Add proposal for someone already in the group"))
  })

  test.concurrent.each(suites)(
    "can't add groupContextExtensions with requiredCapabilities that members don't support %s",
    async (cs) => {
      const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

      const proposalRequiredCapabilities: Proposal = {
        proposalType: defaultProposalTypes.group_context_extensions,
        groupContextExtensions: {
          extensions: [
            {
              extensionType: defaultExtensionTypes.required_capabilities,
              extensionData: encode(requiredCapabilitiesEncoder, {
                extensionTypes: [],
                proposalTypes: [99],
                credentialTypes: [],
              }),
            },
          ],
        },
      }

      await expect(
        createCommit({ state: aliceGroup, cipherSuite: impl }, { extraProposals: [proposalRequiredCapabilities] }),
      ).rejects.toThrow(new ValidationError("Not all members support required capabilities"))
    },
  )

  test.concurrent.each(suites)(
    "can't add groupContextExtensions with requiredCapabilities that newly added member doesn't support %s",
    async (cs) => {
      const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

      const dianaCredential: Credential = {
        credentialType: defaultCredentialTypes.basic,
        identity: new TextEncoder().encode("diana"),
      }
      const diana = await generateKeyPackage(
        dianaCredential,
        { ...defaultCapabilities(), credentials: [defaultCredentialTypes.basic] },
        defaultLifetime,
        [],
        impl,
      )

      const addDiana: Proposal = { proposalType: defaultProposalTypes.add, add: { keyPackage: diana.publicPackage } }

      const proposalRequiredCapabilitiesX509: Proposal = {
        proposalType: defaultProposalTypes.group_context_extensions,
        groupContextExtensions: {
          extensions: [
            {
              extensionType: defaultExtensionTypes.required_capabilities,
              extensionData: encode(requiredCapabilitiesEncoder, {
                extensionTypes: [],
                proposalTypes: [],
                credentialTypes: [defaultCredentialTypes.x509],
              }),
            },
          ],
        },
      }

      await expect(
        createCommit(
          { state: aliceGroup, cipherSuite: impl },
          { extraProposals: [addDiana, proposalRequiredCapabilitiesX509] },
        ),
      ).rejects.toThrow(new ValidationError("Commit contains add proposals of member without required capabilities"))
    },
  )

  test.concurrent.each(suites)("can't add groupContextExtensions with invalid requiredCapabilities %s", async (cs) => {
    const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

    const proposalInvalidRequiredCapabilities: Proposal = {
      proposalType: defaultProposalTypes.group_context_extensions,
      groupContextExtensions: {
        extensions: [
          { extensionType: defaultExtensionTypes.required_capabilities, extensionData: new Uint8Array([1, 2]) },
        ],
      },
    }

    await expect(
      createCommit({ state: aliceGroup, cipherSuite: impl }, { extraProposals: [proposalInvalidRequiredCapabilities] }),
    ).rejects.toThrow(CodecError)
  })

  test.concurrent.each(suites)(
    "can't add groupContextExtensions with external senders that can't be auth'd %s",
    async (cs) => {
      const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

      const proposalInvalidExternalSenders: Proposal = {
        proposalType: defaultProposalTypes.group_context_extensions,
        groupContextExtensions: {
          extensions: [
            { extensionType: defaultExtensionTypes.external_senders, extensionData: new Uint8Array([1, 2]) },
          ],
        },
      }

      await expect(
        createCommit({ state: aliceGroup, cipherSuite: impl }, { extraProposals: [proposalInvalidExternalSenders] }),
      ).rejects.toThrow(CodecError)

      const badCredential = {
        credentialType: defaultCredentialTypes.basic,
        identity: new TextEncoder().encode("NOT GOOD"),
      }
      const proposalUnauthenticatedExternalSenders: Proposal = {
        proposalType: defaultProposalTypes.group_context_extensions,
        groupContextExtensions: {
          extensions: [
            {
              extensionType: defaultExtensionTypes.external_senders,
              extensionData: encode(externalSenderEncoder, {
                credential: badCredential,
                signaturePublicKey: new Uint8Array(),
              }),
            },
          ],
        },
      }

      const authService: AuthenticationService = {
        async validateCredential(c, _pk) {
          if (
            c.credentialType === defaultCredentialTypes.basic &&
            isDefaultCredential(c) &&
            constantTimeEqual(c.identity, badCredential.identity)
          )
            return false
          return true
        },
      }

      await expect(
        createCommit(
          { state: withAuthService(aliceGroup, authService), cipherSuite: impl },
          { extraProposals: [proposalUnauthenticatedExternalSenders] },
        ),
      ).rejects.toThrow(new ValidationError("Could not validate external credential"))
    },
  )

  test.concurrent.each(suites)("can't add a member with invalid credentials %s", async (cs) => {
    const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

    const edwardCredential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("edward"),
    }
    const edward = await generateKeyPackage(
      edwardCredential,
      { ...defaultCapabilities(), credentials: [defaultCredentialTypes.basic] },
      defaultLifetime,
      [],
      impl,
    )
    const addEdward: Proposal = { proposalType: defaultProposalTypes.add, add: { keyPackage: edward.publicPackage } }

    const authServiceEdward: AuthenticationService = {
      async validateCredential(c, _pk) {
        if (
          c.credentialType === defaultCredentialTypes.basic &&
          isDefaultCredential(c) &&
          constantTimeEqual(c.identity, edwardCredential.identity)
        )
          return false
        return true
      },
    }

    await expect(
      createCommit(
        { state: withAuthService(aliceGroup, authServiceEdward), cipherSuite: impl },
        { extraProposals: [addEdward] },
      ),
    ).rejects.toThrow(new ValidationError("Could not validate credential"))
  })

  test.concurrent.each(suites)("can't add leafNode with unsupported credentialType %s", async (cs) => {
    const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

    const frankCredential: Credential = createCustomCredential(5, new Uint8Array([1, 2]))
    const frank = await generateKeyPackage(frankCredential, defaultCapabilities(), defaultLifetime, [], impl)
    const addFrank: Proposal = { proposalType: defaultProposalTypes.add, add: { keyPackage: frank.publicPackage } }

    await expect(
      createCommit({ state: aliceGroup, cipherSuite: impl }, { extraProposals: [addFrank] }),
    ).rejects.toThrow(new ValidationError("LeafNode has credential that is not supported by member of the group"))
  })

  test.concurrent.each(suites)("can't add leafNode with unsupported extension %s", async (cs) => {
    const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

    const georgeCredential: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("george"),
    }
    const georgeExtension: Extension = { extensionType: 8545, extensionData: new Uint8Array() }
    const george = await generateKeyPackage(georgeCredential, defaultCapabilities(), defaultLifetime, [], impl, [
      georgeExtension,
    ])
    const addGeorge: Proposal = { proposalType: defaultProposalTypes.add, add: { keyPackage: george.publicPackage } }

    await expect(
      createCommit({ state: aliceGroup, cipherSuite: impl }, { extraProposals: [addGeorge] }),
    ).rejects.toThrow(new ValidationError("LeafNode contains extension not listed in capabilities"))
  })

  test.concurrent.each(suites)("committer can't update themselves %s", async (cs) => {
    const { impl, aliceGroup, alice } = await setupThreeMembers(cs as CiphersuiteName)

    const updateLeafNode: LeafNode = {
      leafNodeSource: leafNodeSources.update,
      signaturePublicKey: alice.publicPackage.leafNode.signaturePublicKey,
      hpkePublicKey: alice.publicPackage.leafNode.hpkePublicKey,
      credential: alice.publicPackage.leafNode.credential,
      capabilities: alice.publicPackage.leafNode.capabilities,
      extensions: alice.publicPackage.leafNode.extensions,
      signature: new Uint8Array(),
    }

    const updateProposal: Proposal = {
      proposalType: defaultProposalTypes.update,
      update: { leafNode: updateLeafNode },
    }

    await expect(
      createCommit({ state: aliceGroup, cipherSuite: impl }, { extraProposals: [updateProposal] }),
    ).rejects.toThrow(new ValidationError("Commit cannot contain an update proposal sent by committer"))
  })

  test.concurrent.each(suites)("committer can't remove themselves %s", async (cs) => {
    const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

    const removeProposal: ProposalRemove = { proposalType: defaultProposalTypes.remove, remove: { removed: 0 } }

    await expect(
      createCommit({ state: aliceGroup, cipherSuite: impl }, { extraProposals: [removeProposal] }),
    ).rejects.toThrow(new ValidationError("Commit cannot contain a remove proposal removing committer"))
  })

  test.concurrent.each(suites)("can't add the same keypackage twice %s", async (cs) => {
    const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

    const hannahCredential: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("bob"),
    }
    const hannah = await generateKeyPackage(hannahCredential, defaultCapabilities(), defaultLifetime, [], impl)
    const addHannahProposal: ProposalAdd = {
      proposalType: defaultProposalTypes.add,
      add: { keyPackage: hannah.publicPackage },
    }

    await expect(
      createCommit(
        { state: aliceGroup, cipherSuite: impl },
        { extraProposals: [addHannahProposal, addHannahProposal] },
      ),
    ).rejects.toThrow(
      new ValidationError(
        "Commit cannot contain multiple Add proposals that contain KeyPackages that represent the same client",
      ),
    )
  })

  test.concurrent.each(suites)("can't reference the same psk in multiple proposals %s", async (cs) => {
    const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

    const pskId = new Uint8Array([1, 2, 3, 4])
    const pskProposal: Proposal = {
      proposalType: defaultProposalTypes.psk,
      psk: { preSharedKeyId: { psktype: pskTypes.external, pskId, pskNonce: new Uint8Array([5, 6, 7, 8]) } },
    }

    await expect(
      createCommit({ state: aliceGroup, cipherSuite: impl }, { extraProposals: [pskProposal, pskProposal] }),
    ).rejects.toThrow(
      new ValidationError("Commit cannot contain PreSharedKey proposals that reference the same PreSharedKeyID"),
    )
  })

  test.concurrent.each(suites)("can't use multiple group_context_extensions proposals %s", async (cs) => {
    const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

    const groupContextExtensionsProposal: Proposal = {
      proposalType: defaultProposalTypes.group_context_extensions,
      groupContextExtensions: { extensions: [] },
    }

    await expect(
      createCommit(
        { state: aliceGroup, cipherSuite: impl },
        { extraProposals: [groupContextExtensionsProposal, groupContextExtensionsProposal] },
      ),
    ).rejects.toThrow(new ValidationError("Commit cannot contain multiple GroupContextExtensions proposals"))
  })

  test.concurrent.each(suites)("can't use proposeExternal on a group without external_senders %s", async (cs) => {
    const { impl, aliceGroup, charlie } = await setupThreeMembers(cs as CiphersuiteName)

    // external pub not really necessary here
    const groupInfo = await createGroupInfoWithExternalPub(aliceGroup, [], impl)

    const removeBobProposal: ProposalRemove = { proposalType: defaultProposalTypes.remove, remove: { removed: 1 } }

    await expect(
      proposeExternal(
        groupInfo,
        removeBobProposal,
        charlie.publicPackage.leafNode.signaturePublicKey,
        charlie.privatePackage.signaturePrivateKey,
        impl,
      ),
    ).rejects.toThrow(new ValidationError("Could not find external_sender extension in groupContext.extensions"))

    await expect(
      proposeExternal(
        {
          ...groupInfo,
          groupContext: {
            ...groupInfo.groupContext,
            extensions: [
              { extensionType: defaultExtensionTypes.external_senders, extensionData: new Uint8Array([1, 2, 3]) },
            ],
          },
        },
        removeBobProposal,
        charlie.publicPackage.leafNode.signaturePublicKey,
        charlie.privatePackage.signaturePrivateKey,
        impl,
      ),
    ).rejects.toThrow(new ValidationError("Could not decode external_sender extension"))
  })

  test.concurrent.each(suites)(
    "can't use proposeExternal on a group with malformed external_senders %s",
    async (cs) => {
      const { impl, aliceGroup, charlie } = await setupThreeMembers(cs as CiphersuiteName)

      // external pub not really necessary here
      const groupInfo = await createGroupInfoWithExternalPub(aliceGroup, [], impl)

      const removeBobProposal: ProposalRemove = { proposalType: defaultProposalTypes.remove, remove: { removed: 1 } }

      await expect(
        proposeExternal(
          {
            ...groupInfo,
            groupContext: {
              ...groupInfo.groupContext,
              extensions: [
                { extensionType: defaultExtensionTypes.external_senders, extensionData: new Uint8Array([1, 2, 3]) },
              ],
            },
          },
          removeBobProposal,
          charlie.publicPackage.leafNode.signaturePublicKey,
          charlie.privatePackage.signaturePrivateKey,
          impl,
        ),
      ).rejects.toThrow(new ValidationError("Could not decode external_sender extension"))
    },
  )

  test.concurrent.each(suites)("keypackage extension separation %s", async (cs) => {
    const { impl, aliceGroup } = await setupThreeMembers(cs as CiphersuiteName)

    const helenCredential: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("helen"),
    }
    const keyPackageExtension: Extension = {
      extensionType: 1000,
      extensionData: new TextEncoder().encode("keyPackageData"),
    }
    const leafNodeExtension: Extension = {
      extensionType: 2000,
      extensionData: new TextEncoder().encode("leafNodeData"),
    }

    const helenCapabilities: Capabilities = { ...defaultCapabilities(), extensions: [1000, 2000] }

    const helen = await generateKeyPackage(
      helenCredential,
      helenCapabilities,
      defaultLifetime,
      [keyPackageExtension],
      impl,
      [leafNodeExtension],
    )

    expect(helen.publicPackage.extensions).toStrictEqual([keyPackageExtension])
    expect(helen.publicPackage.leafNode.extensions).toStrictEqual([leafNodeExtension])

    const addHelen: Proposal = { proposalType: defaultProposalTypes.add, add: { keyPackage: helen.publicPackage } }
    await createCommit({ state: aliceGroup, cipherSuite: impl }, { extraProposals: [addHelen] })
  })
})

function withAuthService(state: ClientState, authService: AuthenticationService) {
  return { ...state, clientConfig: { ...state.clientConfig, authService: authService } }
}

async function setupThreeMembers(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")
  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: bob.publicPackage },
  }

  const addCharlieProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: charlie.publicPackage },
  }

  const addBobAndCharlieCommitResult = await createCommit(
    { state: aliceGroup, cipherSuite: impl },
    { extraProposals: [addBobProposal, addCharlieProposal] },
  )

  aliceGroup = addBobAndCharlieCommitResult.newState

  const bobGroup = await joinGroup(
    addBobAndCharlieCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  const charlieGroup = await joinGroup(
    addBobAndCharlieCommitResult.welcome!,
    charlie.publicPackage,
    charlie.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  return { impl, alice, aliceGroup, bob, bobGroup, charlie, charlieGroup, addBobProposal }
}
