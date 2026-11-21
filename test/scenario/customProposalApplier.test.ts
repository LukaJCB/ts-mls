import { applyProposals, createGroup, exportSecret, joinGroup, makePskIndex } from "../../src/clientState.js"
import { ClientConfig, CustomProposalApplier, defaultClientConfig } from "../../src/clientConfig.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { Capabilities } from "../../src/capabilities.js"
import { createProposal, unsafeTestingAuthenticationService } from "../../src/index.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { proposalOrRefTypes } from "../../src/proposalOrRefType.js"
import { makeCustomExtension } from "../../src/extension.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"

const SUITE: CiphersuiteName = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"

const customProposalType = 8
const customExtensionType = 6

// Replaces the custom extension with the data of the last custom proposal.
const applier: CustomProposalApplier = (extensions, proposals) => {
  const last = proposals.at(-1)!.proposal
  if (!("proposalData" in last)) throw new Error("Expected custom proposal")
  return [
    ...extensions.filter((e) => e.extensionType !== customExtensionType),
    makeCustomExtension({ extensionType: customExtensionType, extensionData: last.proposalData }),
  ]
}

async function setup() {
  const impl = await getCiphersuiteImpl(SUITE)

  const capabilities: Capabilities = {
    extensions: [customExtensionType],
    credentials: [defaultCredentialTypes.basic],
    proposals: [customProposalType],
    versions: [protocolVersions.mls10],
    ciphersuites: [ciphersuites[SUITE]],
  }

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({ credential: aliceCredential, capabilities, cipherSuite: impl })

  const aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId: new TextEncoder().encode("group1"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({ credential: bobCredential, capabilities, cipherSuite: impl })

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: bob.publicPackage },
  }

  const addBobCommitResult = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    extraProposals: [addBobProposal],
  })

  const bobGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    welcome: addBobCommitResult.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: addBobCommitResult.newState.ratchetTree,
  })

  return { impl, aliceGroup: addBobCommitResult.newState, bobGroup }
}

describe("applyCustomProposals", () => {
  test("custom proposals committed by value and by reference update the GroupContext extensions", async () => {
    const { impl, aliceGroup: alice0, bobGroup: bob0 } = await setup()

    const calls: Parameters<CustomProposalApplier>[] = []
    const clientConfig: ClientConfig = {
      ...defaultClientConfig,
      applyCustomProposals: (extensions, proposals) => {
        calls.push([extensions, proposals])
        return applier(extensions, proposals)
      },
    }
    const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig }

    const byReference: Proposal = { proposalType: customProposalType, proposalData: new Uint8Array([1]) }
    const byValue: Proposal = { proposalType: customProposalType, proposalData: new Uint8Array([2]) }

    const proposalResult = await createProposal({
      context,
      state: bob0,
      wireAsPublicMessage: false,
      proposal: byReference,
    })

    const alice1 = (
      await processMessageEnsureNoMutation({
        context,
        state: alice0,
        message: proposalResult.message,
      })
    ).newState

    const commitResult = await createCommitEnsureNoMutation({
      context,
      state: alice1,
      extraProposals: [byValue],
    })
    const alice2 = commitResult.newState

    const bob2 = (
      await processMessageEnsureNoMutation({
        context,
        state: proposalResult.newState,
        message: commitResult.commit,
      })
    ).newState

    const expected = [makeCustomExtension({ extensionType: customExtensionType, extensionData: new Uint8Array([2]) })]
    expect(alice2.groupContext.extensions).toStrictEqual(expected)
    expect(bob2.groupContext.extensions).toStrictEqual(expected)
    expect(bob2.groupContext.epoch).toBe(alice2.groupContext.epoch)

    // once for the committer, once for the receiver, each with only the custom proposals in commit order
    expect(calls).toHaveLength(2)
    for (const [extensions, proposals] of calls) {
      expect(extensions).toStrictEqual([])
      expect(proposals.map((p) => p.proposal)).toStrictEqual([byReference, byValue])
      expect(proposals.map((p) => p.senderLeafIndex)).toStrictEqual([1, 0])
    }

    await testEveryoneCanMessageEveryone([alice2, bob2], impl)
  })

  test("applier is not called for a Commit without custom proposals", async () => {
    const { impl, aliceGroup, bobGroup } = await setup()

    const applyCustomProposals = vi.fn(applier)
    const clientConfig: ClientConfig = { ...defaultClientConfig, applyCustomProposals }
    const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig }

    const commitResult = await createCommitEnsureNoMutation({ context, state: aliceGroup })
    const bob1 = (await processMessageEnsureNoMutation({ context, state: bobGroup, message: commitResult.commit }))
      .newState

    expect(applyCustomProposals).not.toHaveBeenCalled()
    expect(bob1.groupContext.extensions).toStrictEqual(aliceGroup.groupContext.extensions)
    await testEveryoneCanMessageEveryone([commitResult.newState, bob1], impl)
  })

  test("applier that throws rejects the Commit", async () => {
    const { impl, aliceGroup, bobGroup } = await setup()

    const custom: Proposal = { proposalType: customProposalType, proposalData: new Uint8Array([3]) }

    const commitResult = await createCommitEnsureNoMutation({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        clientConfig: { ...defaultClientConfig, applyCustomProposals: applier },
      },
      state: aliceGroup,
      extraProposals: [custom],
    })

    await expect(
      processMessageEnsureNoMutation({
        context: {
          cipherSuite: impl,
          authService: unsafeTestingAuthenticationService,
          clientConfig: {
            ...defaultClientConfig,
            applyCustomProposals: () => {
              throw new Error("rejected by application")
            },
          },
        },
        state: bobGroup,
        message: commitResult.commit,
      }),
    ).rejects.toThrow("rejected by application")
  })

  test("custom proposals in an external Commit update the GroupContext extensions", async () => {
    const { impl, aliceGroup } = await setup()

    const externalKeyPair = await impl.hpke.deriveKeyPair(aliceGroup.keySchedule.externalSecret)
    const { enc } = await exportSecret(await impl.hpke.exportPublicKey(externalKeyPair.publicKey), impl)

    const custom: Proposal = { proposalType: customProposalType, proposalData: new Uint8Array([4]) }

    const result = await applyProposals(
      aliceGroup,
      aliceGroup.ratchetTree.slice(),
      [
        {
          proposalOrRefType: proposalOrRefTypes.proposal,
          proposal: { proposalType: defaultProposalTypes.external_init, externalInit: { kemOutput: enc } },
        },
        { proposalOrRefType: proposalOrRefTypes.proposal, proposal: custom },
      ],
      undefined,
      makePskIndex(aliceGroup, {}),
      false,
      { ...defaultClientConfig, applyCustomProposals: applier },
      unsafeTestingAuthenticationService,
      impl,
    )

    if (result.additionalResult.kind !== "externalCommit") throw new Error("Expected externalCommit")
    expect(result.additionalResult.extensions).toStrictEqual([
      makeCustomExtension({ extensionType: customExtensionType, extensionData: new Uint8Array([4]) }),
    ])
  })
})
