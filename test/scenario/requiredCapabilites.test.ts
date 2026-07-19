import { ClientState, createGroup, joinGroup } from "../../src/clientState.js"
import { Capabilities } from "../../src/capabilities.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { GroupContextExtension } from "../../src/extension.js"
import { generateKeyPackage, KeyPackage, PrivateKeyPackage } from "../../src/keyPackage.js"
import { ValidationError } from "../../src/mlsError.js"
import { processKeyPackage } from "../../src/processMessages.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { RequiredCapabilities } from "../../src/requiredCapabilities.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"
import { MlsContext } from "../../src/mlsContext.js"
import { CreateCommitResult } from "../../src/createCommit.js"

const oldRequiredCapabilities = requiredCapabilities([7])
const newRequiredCapabilities = requiredCapabilities([9])

describe("Required Capabilities extension", () => {
  test.concurrent.each(Object.keys(ciphersuites))(
    "scenario 1: rejects an add when the group requires unsupported capabilities (%s)",
    async (cs) => {
      const fixture = await setupGroup(cs as CiphersuiteName, { required: oldRequiredCapabilities, alice: [7] })
      const charlie = await fixture.member("charlie", [9])

      await expect(
        processKeyPackage({ context: fixture.context, state: fixture.state, keyPackage: charlie.publicPackage }),
      ).rejects.toThrow(new ValidationError("LeafNode does not support required capabilities"))
    },
  )

  test.concurrent.each(Object.keys(ciphersuites))(
    "scenario 2: group doesn't have reqCaps but gce proposal adds it and current members don't support it (%s)",
    async (cs) => {
      const fixture = await setupGroup(cs as CiphersuiteName, { alice: [7] })

      await expect(fixture.commit([requiredCapabilitiesProposal(newRequiredCapabilities)])).rejects.toThrow(
        new ValidationError("Not all members support required capabilities"),
      )
    },
  )

  test.concurrent.each(Object.keys(ciphersuites))(
    "scenario 3: group doesn't have reqCaps but gce proposal adds it and an add proposal or update proposal doesn't have the caps (%s)",
    async (cs) => {
      const fixture = await setupGroup(cs as CiphersuiteName, { alice: [9] })
      const charlie = await fixture.member("charlie", [7])

      await expect(
        fixture.commit([addProposal(charlie), requiredCapabilitiesProposal(newRequiredCapabilities)]),
      ).rejects.toThrow(new ValidationError("Commit contains proposals of member without required capabilities"))
    },
  )

  test.concurrent.each(Object.keys(ciphersuites))(
    "scenario 4: group doesn't have reqCaps but gce proposal adds it and commiter's new leaf node doesn't have it (%s)",
    async (cs) => {
      const fixture = await setupGroup(cs as CiphersuiteName, { alice: [9] })

      const bob = await fixture.member("bob", [9])
      const addBob = await fixture.commit([addProposal(bob)])
      const aliceGroup = addBob.newState

      const bobState = await joinGroup({
        context: fixture.context,
        welcome: addBob.welcome!.welcome,
        keyPackage: bob.publicPackage,
        privateKeys: bob.privatePackage,
        ratchetTree: addBob.newState.ratchetTree,
      })

      const aliceCommit = await createCommitEnsureNoMutation({
        context: fixture.context,
        state: aliceGroup,
        extraProposals: [requiredCapabilitiesProposal(newRequiredCapabilities)],
        leafNodePatch: { capabilities: fixture.capabilities([7]) },
      })

      await expect(
        processMessageEnsureNoMutation({ context: fixture.context, state: bobState, message: aliceCommit.commit }),
      ).rejects.toThrow(new ValidationError("LeafNode does not support required capabilities"))
    },
  )

  test.concurrent.each(Object.keys(ciphersuites))(
    "sscenario 5: group has reqCaps but gce proposal adds different reqCaps and an add proposal doesn't have the new caps but has the old (%s)",
    async (cs) => {
      const fixture = await setupGroup(cs as CiphersuiteName, { required: oldRequiredCapabilities, alice: [7, 9] })
      const charlie = await fixture.member("charlie", [7])

      await expect(
        fixture.commit([addProposal(charlie), requiredCapabilitiesProposal(newRequiredCapabilities)]),
      ).rejects.toThrow(new ValidationError("Commit contains proposals of member without required capabilities"))
    },
  )

  test.concurrent.each(Object.keys(ciphersuites))(
    "scenario 6: group has reqCaps but gce proposal adds different reqCaps and an add proposal or update proposal has the new caps but not the old",
    async (cs) => {
      const fixture = await setupGroup(cs as CiphersuiteName, { required: oldRequiredCapabilities, alice: [7, 9] })
      const bob = await fixture.member("bob", [7, 9])
      const addBob = await fixture.commit([addProposal(bob)])
      const bobState = await joinGroup({
        context: fixture.context,
        welcome: addBob.welcome!.welcome,
        keyPackage: bob.publicPackage,
        privateKeys: bob.privatePackage,
        ratchetTree: addBob.newState.ratchetTree,
      })
      const charlie = await fixture.member("charlie", [9])

      const commit = await createCommitEnsureNoMutation({
        context: fixture.context,
        state: addBob.newState,
        extraProposals: [addProposal(charlie), requiredCapabilitiesProposal(newRequiredCapabilities)],
      })
      const processed = await processMessageEnsureNoMutation({
        context: fixture.context,
        state: bobState,
        message: commit.commit,
      })

      await testEveryoneCanMessageEveryone([commit.newState, processed.newState], fixture.context.cipherSuite)
    },
  )

  test.concurrent.each(Object.keys(ciphersuites))(
    "scenario 7: group has reqCaps but gce proposal adds different reqCaps and an add proposal or update proposal has neither old or new caps (%s)",
    async (cs) => {
      const fixture = await setupGroup(cs as CiphersuiteName, { required: oldRequiredCapabilities, alice: [7, 9] })
      const charlie = await fixture.member("charlie", [])

      await expect(
        fixture.commit([addProposal(charlie), requiredCapabilitiesProposal(newRequiredCapabilities)]),
      ).rejects.toThrow(new ValidationError("Commit contains proposals of member without required capabilities"))
    },
  )

  test.concurrent.each(Object.keys(ciphersuites))(
    "scenario 8: group has reqCaps but gce proposal adds different reqCaps and an add proposal or update proposal has both old and new caps (%s)",
    async (cs) => {
      const fixture = await setupGroup(cs as CiphersuiteName, { required: oldRequiredCapabilities, alice: [7, 9] })
      const charlie = await fixture.member("charlie", [7, 9])

      await expect(
        fixture.commit([addProposal(charlie), requiredCapabilitiesProposal(newRequiredCapabilities)]),
      ).resolves.toBeDefined()
    },
  )

  test.concurrent.each(Object.keys(ciphersuites))(
    "scenario 9: group has reqCaps but gce proposal adds different reqCaps and a current member doesn't have the new caps but has the old (%s)",
    async (cs) => {
      const fixture = await setupGroup(cs as CiphersuiteName, { required: oldRequiredCapabilities, alice: [7, 9] })

      const bob = await fixture.member("bob", [7])
      const addBob = await fixture.commit([addProposal(bob)])

      await expect(
        createCommitEnsureNoMutation({
          context: fixture.context,
          state: addBob.newState,
          extraProposals: [requiredCapabilitiesProposal(newRequiredCapabilities)],
          leafNodePatch: { capabilities: fixture.capabilities([7]) },
        }),
      ).rejects.toThrow(new ValidationError("Not all members support required capabilities"))
    },
  )

  test.concurrent.each(Object.keys(ciphersuites))(
    "scenario 10: group has reqCaps but gce proposal adds different reqCaps and a current member has both old and new caps (%s)",
    async (cs) => {
      const fixture = await setupGroup(cs as CiphersuiteName, { required: oldRequiredCapabilities, alice: [7, 9] })
      const bob = await fixture.member("bob", [7, 9])
      const addBob = await fixture.commit([addProposal(bob)])
      const bobState = await joinGroup({
        context: fixture.context,
        welcome: addBob.welcome!.welcome,
        keyPackage: bob.publicPackage,
        privateKeys: bob.privatePackage,
        ratchetTree: addBob.newState.ratchetTree,
      })

      const commit = await createCommitEnsureNoMutation({
        context: fixture.context,
        state: addBob.newState,
        extraProposals: [requiredCapabilitiesProposal(newRequiredCapabilities)],
      })

      const processed = await processMessageEnsureNoMutation({
        context: fixture.context,
        state: bobState,
        message: commit.commit,
      })

      await testEveryoneCanMessageEveryone([commit.newState, processed.newState], fixture.context.cipherSuite)
    },
  )
})

function requiredCapabilities(extensionTypes: number[]): RequiredCapabilities {
  return {
    extensionTypes,
    credentialTypes: [defaultCredentialTypes.x509, defaultCredentialTypes.basic],
    proposalTypes: [],
  }
}

function requiredCapabilitiesProposal(required: RequiredCapabilities): Proposal {
  return {
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions: {
      extensions: [
        {
          extensionType: defaultExtensionTypes.required_capabilities,
          extensionData: required,
        },
      ],
    },
  }
}

function addProposal(member: { publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }): ProposalAdd {
  return { proposalType: defaultProposalTypes.add, add: { keyPackage: member.publicPackage } }
}

interface GroupSetup {
  context: MlsContext
  state: ClientState
  capabilities: (extensions: number[]) => Capabilities
  member: (
    identity: string,
    extensions: number[],
  ) => Promise<{ publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }>
  commit: (extraProposals: Proposal[]) => Promise<CreateCommitResult>
}

async function setupGroup(
  cipherSuite: CiphersuiteName,
  options: { required?: RequiredCapabilities; alice: number[] },
): Promise<GroupSetup> {
  const impl = await getCiphersuiteImpl(cipherSuite)
  const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
  const capabilities = (extensions: number[]): Capabilities => ({
    extensions,
    credentials: [defaultCredentialTypes.x509, defaultCredentialTypes.basic],
    proposals: [],
    versions: [protocolVersions.mls10],
    ciphersuites: [ciphersuites[cipherSuite]],
  })
  const member = (identity: string, extensions: number[]) =>
    generateKeyPackage({
      credential: credential(identity),
      capabilities: capabilities(extensions),
      cipherSuite: impl,
    })
  const alice = await member("alice", options.alice)
  const extensions: GroupContextExtension[] = options.required
    ? [
        {
          extensionType: defaultExtensionTypes.required_capabilities,
          extensionData: options.required,
        },
      ]
    : []
  const state = await createGroup({
    context,
    groupId: new TextEncoder().encode("required-capabilities"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
    extensions,
  })

  return {
    context,
    state,
    capabilities,
    member,
    commit: (extraProposals: Proposal[]) => createCommitEnsureNoMutation({ context, state, extraProposals }),
  }
}

function credential(identity: string): Credential {
  return {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode(identity),
  }
}
