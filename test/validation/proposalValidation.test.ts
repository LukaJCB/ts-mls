import { ClientState, createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit, createGroupInfoWithExternalPub } from "../../src/createCommit.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd, ProposalRemove } from "../../src/proposal.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { CodecError, ValidationError } from "../../src/mlsError.js"
import { encodeRequiredCapabilities } from "../../src/requiredCapabilities.js"
import { encodeExternalSender } from "../../src/externalSender.js"
import { AuthenticationService } from "../../src/authenticationService.js"
import { constantTimeEqual } from "../../src/util/constantTimeCompare.js"
import { createCustomCredential } from "../../src/customCredential.js"
import { Extension } from "../../src/extension.js"
import { LeafNode } from "../../src/leafNode.js"
import { proposeExternal } from "../../src/index.js"

test.concurrent.each(Object.keys(ciphersuites))(`Proposal Validation %s`, async (cs) => {
  await remove(cs as CiphersuiteName)
})

async function remove(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addCharlieProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: charlie.publicPackage,
    },
  }

  const addBobAndCharlieCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    {
      extraProposals: [addBobProposal, addCharlieProposal],
    },
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

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const charlieGroup = await joinGroup(
    addBobAndCharlieCommitResult.welcome!,
    charlie.publicPackage,
    charlie.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const removeBobProposal: ProposalRemove = {
    proposalType: "remove",
    remove: {
      removed: bobGroup.privatePath.leafIndex,
    },
  }

  const removeBobProposal2: ProposalRemove = {
    proposalType: "remove",
    remove: {
      removed: bobGroup.privatePath.leafIndex,
    },
  }

  // can't remove same leaf node twice
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [removeBobProposal, removeBobProposal2],
      },
    ),
  ).rejects.toThrow(ValidationError)

  // can't add someone already in the group
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [addBobProposal],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const proposalInvalidRequiredCapabilities: Proposal = {
    proposalType: "group_context_extensions",
    groupContextExtensions: {
      extensions: [{ extensionType: "required_capabilities", extensionData: new Uint8Array([1, 2]) }],
    },
  }

  //can't add groupContextExtensions with invalid requiredCapabilities
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [proposalInvalidRequiredCapabilities],
      },
    ),
  ).rejects.toThrow(CodecError)

  const proposalRequiredCapabilities: Proposal = {
    proposalType: "group_context_extensions",
    groupContextExtensions: {
      extensions: [
        {
          extensionType: "required_capabilities",
          extensionData: encodeRequiredCapabilities({ extensionTypes: [], proposalTypes: [99], credentialTypes: [] }),
        },
      ],
    },
  }

  //can't add groupContextExtensions with requiredCapabilities that members don't support
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [proposalRequiredCapabilities],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const dianaCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("diana") }
  const diana = await generateKeyPackage(
    dianaCredential,
    { ...defaultCapabilities(), credentials: ["basic"] },
    defaultLifetime,
    [],
    impl,
  )

  const addDiana: Proposal = {
    proposalType: "add",
    add: {
      keyPackage: diana.publicPackage,
    },
  }

  const proposalRequiredCapabilitiesX509: Proposal = {
    proposalType: "group_context_extensions",
    groupContextExtensions: {
      extensions: [
        {
          extensionType: "required_capabilities",
          extensionData: encodeRequiredCapabilities({
            extensionTypes: [],
            proposalTypes: [],
            credentialTypes: ["x509"],
          }),
        },
      ],
    },
  }

  //can't add groupContextExtensions with requiredCapabilities that newly added member doesn't support
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [addDiana, proposalRequiredCapabilitiesX509],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const proposalInvalidExternalSenders: Proposal = {
    proposalType: "group_context_extensions",
    groupContextExtensions: {
      extensions: [{ extensionType: "external_senders", extensionData: new Uint8Array([1, 2]) }],
    },
  }

  //can't add groupContextExtensions with invalid requiredCapabilities
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [proposalInvalidExternalSenders],
      },
    ),
  ).rejects.toThrow(CodecError)

  const badCredential = { credentialType: "basic" as const, identity: new TextEncoder().encode("NOT GOOD") }

  const proposalUnauthenticatedExternalSenders: Proposal = {
    proposalType: "group_context_extensions",
    groupContextExtensions: {
      extensions: [
        {
          extensionType: "external_senders",
          extensionData: encodeExternalSender({ credential: badCredential, signaturePublicKey: new Uint8Array() }),
        },
      ],
    },
  }

  const authService: AuthenticationService = {
    async validateCredential(c, _pk) {
      if (c.credentialType === "basic" && constantTimeEqual(c.identity, badCredential.identity)) return false
      return true
    },
  }

  //can't add groupContextExtensions with external senders that can't be auth'd
  await expect(
    createCommit(
      {
        state: withAuthService(aliceGroup, authService),
        cipherSuite: impl,
      },
      {
        extraProposals: [proposalUnauthenticatedExternalSenders],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const edwardCredential = { credentialType: "basic" as const, identity: new TextEncoder().encode("edward") }
  const edward = await generateKeyPackage(
    edwardCredential,
    { ...defaultCapabilities(), credentials: ["basic"] },
    defaultLifetime,
    [],
    impl,
  )

  const addEdward: Proposal = {
    proposalType: "add",
    add: {
      keyPackage: edward.publicPackage,
    },
  }

  const authServiceEdward: AuthenticationService = {
    async validateCredential(c, _pk) {
      if (c.credentialType === "basic" && constantTimeEqual(c.identity, edwardCredential.identity)) return false
      return true
    },
  }

  //can't add a member with invalid credentials
  await expect(
    createCommit(
      {
        state: withAuthService(aliceGroup, authServiceEdward),
        cipherSuite: impl,
      },
      {
        extraProposals: [addEdward],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const frankCredential: Credential = createCustomCredential(5, new Uint8Array([1, 2]))
  const frank = await generateKeyPackage(frankCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addFrank: Proposal = {
    proposalType: "add",
    add: { keyPackage: frank.publicPackage },
  }

  //can't add leafNode with an unsupported credentialType
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [addFrank],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const georgeCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("george") }
  const georgeExtension: Extension = { extensionType: 8545, extensionData: new Uint8Array() }
  const george = await generateKeyPackage(
    georgeCredential,
    defaultCapabilities(),
    defaultLifetime,
    [georgeExtension],
    impl,
  )

  const addGeorge: Proposal = {
    proposalType: "add",
    add: { keyPackage: george.publicPackage },
  }

  //can't add leafNode with an unsupported extension
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [addGeorge],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const updateLeafNode: LeafNode = {
    leafNodeSource: "update",
    signaturePublicKey: alice.publicPackage.leafNode.signaturePublicKey,
    hpkePublicKey: alice.publicPackage.leafNode.hpkePublicKey,
    credential: alice.publicPackage.leafNode.credential,
    capabilities: alice.publicPackage.leafNode.capabilities,
    extensions: alice.publicPackage.leafNode.extensions,
    signature: new Uint8Array(),
  }

  const updateProposal: Proposal = {
    proposalType: "update",
    update: {
      leafNode: updateLeafNode,
    },
  }

  // commiter can't update themselves
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [updateProposal],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const removeProposal: ProposalRemove = {
    proposalType: "remove",
    remove: {
      removed: 0,
    },
  }

  // committer can't remove themselves
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [removeProposal],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const hannahCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const hannah = await generateKeyPackage(hannahCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addHannahProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: hannah.publicPackage,
    },
  }

  // can't add the same  keypackage twice
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [addHannahProposal, addHannahProposal],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const pskId = new Uint8Array([1, 2, 3, 4])
  const pskProposal: Proposal = {
    proposalType: "psk",
    psk: {
      preSharedKeyId: {
        psktype: "external",
        pskId,
        pskNonce: new Uint8Array([5, 6, 7, 8]),
      },
    },
  }

  // can't reference the same psk in multiple proposals
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [pskProposal, pskProposal],
      },
    ),
  ).rejects.toThrow(ValidationError)

  const groupContextExtensionsProposal: Proposal = {
    proposalType: "group_context_extensions",
    groupContextExtensions: {
      extensions: [],
    },
  }

  // can't use multiple group_context_extensions proposals
  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      {
        extraProposals: [groupContextExtensionsProposal, groupContextExtensionsProposal],
      },
    ),
  ).rejects.toThrow(ValidationError)

  // external pub not really necessary here
  const groupInfo = await createGroupInfoWithExternalPub(aliceGroup, [], impl)

  // can't use proposeExternal on a group without external_senders
  await expect(
    proposeExternal(
      groupInfo,
      removeBobProposal,
      charlie.publicPackage.leafNode.signaturePublicKey,
      charlie.privatePackage.signaturePrivateKey,
      impl,
    ),
  ).rejects.toThrow(ValidationError)

  // can't use proposeExternal on a group with malformed external_senders
  await expect(
    proposeExternal(
      {
        ...groupInfo,
        groupContext: {
          ...groupInfo.groupContext,
          extensions: [{ extensionType: "external_senders", extensionData: new Uint8Array([1, 2, 3]) }],
        },
      },
      removeBobProposal,
      charlie.publicPackage.leafNode.signaturePublicKey,
      charlie.privatePackage.signaturePrivateKey,
      impl,
    ),
  ).rejects.toThrow(ValidationError)
}

function withAuthService(state: ClientState, authService: AuthenticationService) {
  return { ...state, clientConfig: { ...state.clientConfig, authService: authService } }
}
