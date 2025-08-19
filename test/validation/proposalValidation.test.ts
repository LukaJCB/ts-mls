import { ClientState, createGroup, joinGroup } from "../../src/clientState"
import { createCommit, createGroupInfoWithExternalPub } from "../../src/createCommit"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { Proposal, ProposalAdd, ProposalRemove } from "../../src/proposal"
import { defaultLifetime } from "../../src/lifetime"
import { defaultCapabilities } from "../../src/defaultCapabilities"
import { CodecError, ValidationError } from "../../src/mlsError"
import { encodeRequiredCapabilities } from "../../src/requiredCapabilities"
import { encodeExternalSender } from "../../src/externalSender"
import { AuthenticationService } from "../../src/authenticationService"
import { constantTimeEqual } from "../../src/util/constantTimeCompare"
import { createCustomCredential } from "../../src/customCredential"
import { Extension } from "../../src/extension"
import { LeafNode } from "../../src/leafNode"
import { proposeExternal } from "../../src"

for (const cs of Object.keys(ciphersuites)) {
  test(`Proposal Validation ${cs}`, async () => {
    await remove(cs as CiphersuiteName)
  })
}

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
    aliceGroup,
    emptyPskIndex,
    false,
    [addBobProposal, addCharlieProposal],
    impl,
  )

  aliceGroup = addBobAndCharlieCommitResult.newState

  let bobGroup = await joinGroup(
    addBobAndCharlieCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  let charlieGroup = await joinGroup(
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
    createCommit(aliceGroup, emptyPskIndex, false, [removeBobProposal, removeBobProposal2], impl),
  ).rejects.toThrow(ValidationError)

  // can't add someone already in the group
  await expect(createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)).rejects.toThrow(ValidationError)

  const proposalInvalidRequiredCapabilities: Proposal = {
    proposalType: "group_context_extensions",
    groupContextExtensions: {
      extensions: [{ extensionType: "required_capabilities", extensionData: new Uint8Array([1, 2]) }],
    },
  }

  //can't add groupContextExtensions with invalid requiredCapabilities
  await expect(
    createCommit(aliceGroup, emptyPskIndex, false, [proposalInvalidRequiredCapabilities], impl),
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
  await expect(createCommit(aliceGroup, emptyPskIndex, false, [proposalRequiredCapabilities], impl)).rejects.toThrow(
    ValidationError,
  )

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
    createCommit(aliceGroup, emptyPskIndex, false, [addDiana, proposalRequiredCapabilitiesX509], impl),
  ).rejects.toThrow(ValidationError)

  const proposalInvalidExternalSenders: Proposal = {
    proposalType: "group_context_extensions",
    groupContextExtensions: {
      extensions: [{ extensionType: "external_senders", extensionData: new Uint8Array([1, 2]) }],
    },
  }

  //can't add groupContextExtensions with invalid requiredCapabilities
  await expect(createCommit(aliceGroup, emptyPskIndex, false, [proposalInvalidExternalSenders], impl)).rejects.toThrow(
    CodecError,
  )

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
      withAuthService(aliceGroup, authService),
      emptyPskIndex,
      false,
      [proposalUnauthenticatedExternalSenders],
      impl,
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
    createCommit(withAuthService(aliceGroup, authServiceEdward), emptyPskIndex, false, [addEdward], impl),
  ).rejects.toThrow(ValidationError)

  const frankCredential: Credential = createCustomCredential(5, new Uint8Array([1, 2]))
  const frank = await generateKeyPackage(frankCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addFrank: Proposal = {
    proposalType: "add",
    add: { keyPackage: frank.publicPackage },
  }

  //can't add leafNode with an unsupported credentialType
  await expect(createCommit(aliceGroup, emptyPskIndex, false, [addFrank], impl)).rejects.toThrow(ValidationError)

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
  await expect(createCommit(aliceGroup, emptyPskIndex, false, [addGeorge], impl)).rejects.toThrow(ValidationError)

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
  await expect(createCommit(aliceGroup, emptyPskIndex, false, [updateProposal], impl)).rejects.toThrow(ValidationError)

  const removeProposal: ProposalRemove = {
    proposalType: "remove",
    remove: {
      removed: 0,
    },
  }

  // committer can't remove themselves
  await expect(createCommit(aliceGroup, emptyPskIndex, false, [removeProposal], impl)).rejects.toThrow(ValidationError)

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
    createCommit(aliceGroup, emptyPskIndex, false, [addHannahProposal, addHannahProposal], impl),
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
  await expect(createCommit(aliceGroup, emptyPskIndex, false, [pskProposal, pskProposal], impl)).rejects.toThrow(
    ValidationError,
  )

  const groupContextExtensionsProposal: Proposal = {
    proposalType: "group_context_extensions",
    groupContextExtensions: {
      extensions: [],
    },
  }

  // can't use multiple group_context_extensions proposals
  await expect(
    createCommit(
      aliceGroup,
      emptyPskIndex,
      false,
      [groupContextExtensionsProposal, groupContextExtensionsProposal],
      impl,
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
