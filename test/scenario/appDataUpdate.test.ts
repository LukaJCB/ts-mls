import { ClientState, createGroup, joinGroup } from "../../src/clientState.js"
import { ClientConfig, defaultClientConfig } from "../../src/clientConfig.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteImpl, CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAppDataUpdate } from "../../src/proposal.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { defaultExtensionTypes } from "../../src/defaultExtensionType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { Capabilities } from "../../src/capabilities.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import {
  AppDataDictionary,
  appDataDictionaryExtensionType,
  getAppDataDictionary,
  makeAppDataDictionaryExtension,
} from "../../src/appDataDictionary.js"
import { appDataUpdateProposalType } from "../../src/appDataUpdate.js"
import { GroupContextExtension } from "../../src/extension.js"
import { ValidationError } from "../../src/mlsError.js"
import { createProposal } from "../../src/createMessage.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"

const defaultSuite: CiphersuiteName = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"

const componentId = 0x8001
const otherComponentId = 0x8002

test.concurrent.each(Object.keys(ciphersuites))(
  `Commit with AppDataUpdate proposal updates the app_data_dictionary %s`,
  async (cs) => {
    await appDataUpdateCommitTest(cs as CiphersuiteName)
  },
)

function appDataCapabilities(cipherSuite: CiphersuiteName): Capabilities {
  return {
    extensions: [appDataDictionaryExtensionType],
    credentials: [defaultCredentialTypes.basic],
    proposals: [appDataUpdateProposalType],
    versions: [protocolVersions.mls10],
    ciphersuites: [ciphersuites[cipherSuite]],
  }
}

function updateProposal(component: number, data: Uint8Array): ProposalAppDataUpdate {
  return {
    proposalType: appDataUpdateProposalType,
    appDataUpdate: { componentId: component, operation: "update", update: data },
  }
}

function removeProposal(component: number): ProposalAppDataUpdate {
  return {
    proposalType: appDataUpdateProposalType,
    appDataUpdate: { componentId: component, operation: "remove" },
  }
}

function dictionaryOf(state: ClientState): AppDataDictionary | undefined {
  return getAppDataDictionary(state.groupContext.extensions)
}

/** Builds a two member group where alice is the committer and bob joined via welcome. */
async function setup(
  cipherSuite: CiphersuiteName,
  impl: CiphersuiteImpl,
  extensions: GroupContextExtension[],
  clientConfig?: ClientConfig,
): Promise<{ aliceGroup: ClientState; bobGroup: ClientState }> {
  const capabilities = appDataCapabilities(cipherSuite)

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({ credential: aliceCredential, capabilities, cipherSuite: impl })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({ credential: bobCredential, capabilities, cipherSuite: impl })

  const aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    groupId: new TextEncoder().encode("group1"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
    extensions,
  })

  const addBobCommit = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    state: aliceGroup,
    extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
    ratchetTreeExtension: true,
  })

  const bobGroup = await joinGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    welcome: addBobCommit.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
  })

  return { aliceGroup: addBobCommit.newState, bobGroup }
}

/** Commits the proposals at alice and processes the commit at bob. */
async function commitAndProcess(
  impl: CiphersuiteImpl,
  aliceGroup: ClientState,
  bobGroup: ClientState,
  proposals: Proposal[],
  clientConfig?: ClientConfig,
): Promise<{ aliceGroup: ClientState; bobGroup: ClientState }> {
  const commitResult = await createCommitEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    state: aliceGroup,
    extraProposals: proposals,
  })

  const processResult = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService, clientConfig },
    state: bobGroup,
    message: commitResult.commit,
  })

  if (processResult.kind !== "newState") throw new Error("Expected new state")

  return { aliceGroup: commitResult.newState, bobGroup: processResult.newState }
}

async function appDataUpdateCommitTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

  const initialDictionary: AppDataDictionary = [{ componentId, data: new Uint8Array([0]) }]

  let { aliceGroup, bobGroup } = await setup(cipherSuite, impl, [makeAppDataDictionaryExtension(initialDictionary)])

  expect(dictionaryOf(bobGroup)).toStrictEqual(initialDictionary)

  const newData = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
  ;({ aliceGroup, bobGroup } = await commitAndProcess(impl, aliceGroup, bobGroup, [
    updateProposal(componentId, newData),
  ]))

  const expected: AppDataDictionary = [{ componentId, data: newData }]
  expect(dictionaryOf(aliceGroup)).toStrictEqual(expected)
  expect(dictionaryOf(bobGroup)).toStrictEqual(expected)
  expect(bobGroup.groupContext.epoch).toBe(aliceGroup.groupContext.epoch)

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}

test("AppDataUpdate creates the app_data_dictionary extension when absent", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  let { aliceGroup, bobGroup } = await setup(defaultSuite, impl, [])

  expect(dictionaryOf(aliceGroup)).toBeUndefined()

  const data = new Uint8Array([1, 2, 3])
  ;({ aliceGroup, bobGroup } = await commitAndProcess(impl, aliceGroup, bobGroup, [updateProposal(componentId, data)]))

  const expected: AppDataDictionary = [{ componentId, data }]
  expect(dictionaryOf(aliceGroup)).toStrictEqual(expected)
  expect(dictionaryOf(bobGroup)).toStrictEqual(expected)
})

test("Multiple AppDataUpdate proposals for the same component apply in order (last update wins by default)", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  let { aliceGroup, bobGroup } = await setup(defaultSuite, impl, [])

  const last = new Uint8Array([9])
  ;({ aliceGroup, bobGroup } = await commitAndProcess(impl, aliceGroup, bobGroup, [
    updateProposal(componentId, new Uint8Array([1])),
    updateProposal(componentId, new Uint8Array([2])),
    updateProposal(componentId, last),
  ]))

  expect(dictionaryOf(aliceGroup)).toStrictEqual([{ componentId, data: last }])
  expect(dictionaryOf(bobGroup)).toStrictEqual([{ componentId, data: last }])
})

test("A custom appDataUpdateCallback controls how updates are applied", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  // application logic that concatenates all updates onto the current data
  const clientConfig: ClientConfig = {
    ...defaultClientConfig,
    appDataUpdateCallback: (_componentId, currentData, updates) => {
      const parts = [currentData ?? new Uint8Array([]), ...updates]
      const result = new Uint8Array(parts.reduce((acc, p) => acc + p.length, 0))
      let offset = 0
      for (const part of parts) {
        result.set(part, offset)
        offset += part.length
      }
      return result
    },
  }

  const initialDictionary: AppDataDictionary = [{ componentId, data: new Uint8Array([0]) }]

  let { aliceGroup, bobGroup } = await setup(
    defaultSuite,
    impl,
    [makeAppDataDictionaryExtension(initialDictionary)],
    clientConfig,
  )
  ;({ aliceGroup, bobGroup } = await commitAndProcess(
    impl,
    aliceGroup,
    bobGroup,
    [updateProposal(componentId, new Uint8Array([1])), updateProposal(componentId, new Uint8Array([2]))],
    clientConfig,
  ))

  const expected: AppDataDictionary = [{ componentId, data: new Uint8Array([0, 1, 2]) }]
  expect(dictionaryOf(aliceGroup)).toStrictEqual(expected)
  expect(dictionaryOf(bobGroup)).toStrictEqual(expected)
})

test("AppDataUpdate remove operation removes the component entry", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  const initialDictionary: AppDataDictionary = [
    { componentId, data: new Uint8Array([1]) },
    { componentId: otherComponentId, data: new Uint8Array([2]) },
  ]

  let { aliceGroup, bobGroup } = await setup(defaultSuite, impl, [makeAppDataDictionaryExtension(initialDictionary)])
  ;({ aliceGroup, bobGroup } = await commitAndProcess(impl, aliceGroup, bobGroup, [removeProposal(componentId)]))

  const expected: AppDataDictionary = [{ componentId: otherComponentId, data: new Uint8Array([2]) }]
  expect(dictionaryOf(aliceGroup)).toStrictEqual(expected)
  expect(dictionaryOf(bobGroup)).toStrictEqual(expected)
})

test("AppDataUpdate inserts new components sorted by componentId", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  const initialDictionary: AppDataDictionary = [{ componentId: otherComponentId, data: new Uint8Array([2]) }]

  let { aliceGroup, bobGroup } = await setup(defaultSuite, impl, [makeAppDataDictionaryExtension(initialDictionary)])
  ;({ aliceGroup, bobGroup } = await commitAndProcess(impl, aliceGroup, bobGroup, [
    updateProposal(componentId, new Uint8Array([1])),
  ]))

  const expected: AppDataDictionary = [
    { componentId, data: new Uint8Array([1]) },
    { componentId: otherComponentId, data: new Uint8Array([2]) },
  ]
  expect(dictionaryOf(aliceGroup)).toStrictEqual(expected)
  expect(dictionaryOf(bobGroup)).toStrictEqual(expected)
})

test("AppDataUpdate remove for a component without state is invalid", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  const { aliceGroup } = await setup(defaultSuite, impl, [])

  await expect(
    createCommitEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      extraProposals: [removeProposal(componentId)],
    }),
  ).rejects.toThrow(ValidationError)
})

test("AppDataUpdate update and remove for the same component is invalid", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  const initialDictionary: AppDataDictionary = [{ componentId, data: new Uint8Array([1]) }]
  const { aliceGroup } = await setup(defaultSuite, impl, [makeAppDataDictionaryExtension(initialDictionary)])

  await expect(
    createCommitEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      extraProposals: [updateProposal(componentId, new Uint8Array([2])), removeProposal(componentId)],
    }),
  ).rejects.toThrow(ValidationError)
})

test("Multiple AppDataUpdate removes for the same component are invalid", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  const initialDictionary: AppDataDictionary = [{ componentId, data: new Uint8Array([1]) }]
  const { aliceGroup } = await setup(defaultSuite, impl, [makeAppDataDictionaryExtension(initialDictionary)])

  await expect(
    createCommitEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      extraProposals: [removeProposal(componentId), removeProposal(componentId)],
    }),
  ).rejects.toThrow(ValidationError)
})

test("AppDataUpdate works as a standalone proposal that is committed later", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  const initialDictionary: AppDataDictionary = [{ componentId, data: new Uint8Array([0]) }]

  let { aliceGroup, bobGroup } = await setup(defaultSuite, impl, [makeAppDataDictionaryExtension(initialDictionary)])

  const data = new Uint8Array([1, 2, 3])

  // bob sends a standalone proposal
  const proposalResult = await createProposal({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    wireAsPublicMessage: false,
    proposal: updateProposal(componentId, data),
  })
  bobGroup = proposalResult.newState

  // alice receives the proposal and commits it
  const processProposalResult = await processMessageEnsureNoMutation({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    message: proposalResult.message,
  })
  if (processProposalResult.kind !== "newState") throw new Error("Expected new state")
  aliceGroup = processProposalResult.newState
  ;({ aliceGroup, bobGroup } = await commitAndProcess(impl, aliceGroup, bobGroup, []))

  const expected: AppDataDictionary = [{ componentId, data }]
  expect(dictionaryOf(aliceGroup)).toStrictEqual(expected)
  expect(dictionaryOf(bobGroup)).toStrictEqual(expected)
})

test("GroupContextExtensions and AppDataUpdate proposals can be combined in one commit", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  const initialDictionary: AppDataDictionary = [{ componentId, data: new Uint8Array([0]) }]

  let { aliceGroup, bobGroup } = await setup(defaultSuite, impl, [makeAppDataDictionaryExtension(initialDictionary)])

  const newData = new Uint8Array([1])
  const gceProposal: Proposal = {
    proposalType: defaultProposalTypes.group_context_extensions,
    // GCE replaces the whole extension set; carry the dictionary forward unchanged
    groupContextExtensions: { extensions: aliceGroup.groupContext.extensions },
  }

  ;({ aliceGroup, bobGroup } = await commitAndProcess(impl, aliceGroup, bobGroup, [
    gceProposal,
    updateProposal(componentId, newData),
  ]))

  const expected: AppDataDictionary = [{ componentId, data: newData }]
  expect(dictionaryOf(aliceGroup)).toStrictEqual(expected)
  expect(dictionaryOf(bobGroup)).toStrictEqual(expected)
})

test("AppDataUpdate proposals cannot appear before a GroupContextExtensions proposal", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  const initialDictionary: AppDataDictionary = [{ componentId, data: new Uint8Array([0]) }]
  const { aliceGroup } = await setup(defaultSuite, impl, [makeAppDataDictionaryExtension(initialDictionary)])

  const gceProposal: Proposal = {
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions: { extensions: aliceGroup.groupContext.extensions },
  }

  await expect(
    createCommitEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      extraProposals: [updateProposal(componentId, new Uint8Array([1])), gceProposal],
    }),
  ).rejects.toThrow(ValidationError)
})

test("GroupContextExtensions cannot drop the AppDataUpdate required capability while modifying the dictionary", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  const initialDictionary: AppDataDictionary = [{ componentId, data: new Uint8Array([0]) }]
  const requiredCapabilities: GroupContextExtension = {
    extensionType: defaultExtensionTypes.required_capabilities,
    extensionData: {
      extensionTypes: [appDataDictionaryExtensionType],
      proposalTypes: [appDataUpdateProposalType],
      credentialTypes: [],
    },
  }

  const { aliceGroup } = await setup(defaultSuite, impl, [
    requiredCapabilities,
    makeAppDataDictionaryExtension(initialDictionary),
  ])

  // the proposed extensions no longer require the AppDataUpdate proposal type and
  // at the same time replace the dictionary; the current group context still
  // requires it, so the dictionary must remain protected
  const gceProposal: Proposal = {
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions: {
      extensions: [makeAppDataDictionaryExtension([{ componentId, data: new Uint8Array([0xff]) }])],
    },
  }

  await expect(
    createCommitEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      extraProposals: [gceProposal],
    }),
  ).rejects.toThrow(ValidationError)
})

test("A partial ClientConfig without appDataUpdateCallback falls back to the default", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  // simulates a JS caller that constructed its config before appDataUpdateCallback existed
  const partialClientConfig = {} as ClientConfig

  const initialDictionary: AppDataDictionary = [{ componentId, data: new Uint8Array([0]) }]

  let { aliceGroup, bobGroup } = await setup(
    defaultSuite,
    impl,
    [makeAppDataDictionaryExtension(initialDictionary)],
    partialClientConfig,
  )

  const newData = new Uint8Array([1, 2, 3])
  ;({ aliceGroup, bobGroup } = await commitAndProcess(
    impl,
    aliceGroup,
    bobGroup,
    [updateProposal(componentId, newData)],
    partialClientConfig,
  ))

  const expected: AppDataDictionary = [{ componentId, data: newData }]
  expect(dictionaryOf(aliceGroup)).toStrictEqual(expected)
  expect(dictionaryOf(bobGroup)).toStrictEqual(expected)
})

test("GroupContextExtensions cannot modify the dictionary when required capabilities include AppDataUpdate", async () => {
  const impl = await getCiphersuiteImpl(defaultSuite)

  const initialDictionary: AppDataDictionary = [{ componentId, data: new Uint8Array([0]) }]
  const requiredCapabilities: GroupContextExtension = {
    extensionType: defaultExtensionTypes.required_capabilities,
    extensionData: {
      extensionTypes: [appDataDictionaryExtensionType],
      proposalTypes: [appDataUpdateProposalType],
      credentialTypes: [],
    },
  }

  const { aliceGroup } = await setup(defaultSuite, impl, [
    requiredCapabilities,
    makeAppDataDictionaryExtension(initialDictionary),
  ])

  const gceProposal: Proposal = {
    proposalType: defaultProposalTypes.group_context_extensions,
    groupContextExtensions: {
      extensions: aliceGroup.groupContext.extensions.map((e) =>
        e.extensionType === appDataDictionaryExtensionType
          ? makeAppDataDictionaryExtension([{ componentId, data: new Uint8Array([0xff]) }])
          : e,
      ),
    },
  }

  await expect(
    createCommitEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      extraProposals: [gceProposal],
    }),
  ).rejects.toThrow(ValidationError)
})
