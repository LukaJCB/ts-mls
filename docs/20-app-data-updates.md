# Application Data Updates

This scenario demonstrates the `app_data_dictionary` GroupContext extension and the `app_data_update` proposal from [draft-ietf-mls-extensions-09](https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions-09). Together they let applications store opaque per-component data in the GroupContext — agreed on by all members and automatically distributed to new joiners — and update individual components without resending the whole extension set or requiring an UpdatePath.

## Steps Covered

1. **Setup Capabilities**: Members advertise the `app_data_dictionary` extension and `app_data_update` proposal types.
2. **Group Creation**: Alice creates a group whose GroupContext carries an initial dictionary.
3. **Joining**: Bob joins and receives the dictionary as part of the GroupContext.
4. **Update Commit**: Alice commits an `app_data_update` proposal that replaces one component's data.
5. **Process Commit**: Bob processes the commit; both members converge on the new dictionary.

## Key Concepts

- **AppDataDictionary**: A list of `ComponentData` entries, each associating opaque application data with a `componentId` (a `uint16`). Entries are sorted by componentId with at most one entry per componentId.
- **AppDataUpdate Proposal**: Updates or removes a single component's entry. Because the proposal is applied while forming the new GroupContext, the updated dictionary is folded into the confirmed transcript, the key schedule, and the confirmation tag.
- **Application Logic**: The update payloads are opaque to MLS. The `appDataUpdateCallback` in the `ClientConfig` decides how update payloads transform a component's data. The default treats each update as a full replacement (the last update for a component wins). All members must use the same logic to converge.
- **Capabilities**: Members must advertise extension type `6` and proposal type `8` in their capabilities.

---

```typescript
import {
  createGroup,
  joinGroup,
  createCommit,
  processMessage,
  Credential,
  defaultCredentialTypes,
  getCiphersuiteImpl,
  generateKeyPackage,
  Capabilities,
  protocolVersions,
  ciphersuites,
  defaultProposalTypes,
  unsafeTestingAuthenticationService,
  appDataDictionaryExtensionType,
  appDataUpdateProposalType,
  makeAppDataDictionaryExtension,
  getAppDataDictionary,
  ProposalAppDataUpdate,
  zeroOutUint8Array,
} from "ts-mls"

// Setup ciphersuite
const impl = await getCiphersuiteImpl("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }

// Application components use ids in the private use range (0x8000 - 0xFFFF)
const componentId = 0x8001

// Members must advertise the app_data_dictionary extension and
// the app_data_update proposal in their capabilities
const capabilities: Capabilities = {
  extensions: [appDataDictionaryExtensionType],
  credentials: [defaultCredentialTypes.basic],
  proposals: [appDataUpdateProposalType],
  versions: [protocolVersions.mls10],
  ciphersuites: [ciphersuites["MLS_256_XWING_AES256GCM_SHA512_Ed25519"]],
}

// Setup Alice's credential
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({
  credential: aliceCredential,
  capabilities,
  cipherSuite: impl,
})

const groupId = new TextEncoder().encode("group1")

// Alice creates the group with an initial dictionary in the GroupContext
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
  extensions: [makeAppDataDictionaryExtension([{ componentId, data: new TextEncoder().encode("initial state") }])],
})

// Setup Bob's credential
const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage({
  credential: bobCredential,
  capabilities,
  cipherSuite: impl,
})

// Alice adds Bob to the group
const addBobCommitResult = await createCommit({
  context,
  state: aliceGroup,
  extraProposals: [
    {
      proposalType: defaultProposalTypes.add,
      add: {
        keyPackage: bob.publicPackage,
      },
    },
  ],
})

aliceGroup = addBobCommitResult.newState
addBobCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob joins the group and receives the dictionary as part of the GroupContext
let bobGroup = await joinGroup({
  context,
  welcome: addBobCommitResult.welcome!.welcome,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Alice updates the component's data with an app_data_update proposal
const appDataUpdate: ProposalAppDataUpdate = {
  proposalType: appDataUpdateProposalType,
  appDataUpdate: {
    componentId,
    operation: "update",
    update: new TextEncoder().encode("updated state"),
  },
}

const updateCommitResult = await createCommit({
  context,
  state: aliceGroup,
  extraProposals: [appDataUpdate],
})

aliceGroup = updateCommitResult.newState
updateCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob processes the commit and converges on the same dictionary
const processCommitResult = await processMessage({
  context,
  state: bobGroup,
  message: updateCommitResult.commit,
})

bobGroup = processCommitResult.newState
processCommitResult.consumed.forEach(zeroOutUint8Array)

// Both members now see the updated dictionary in their GroupContext
const aliceDictionary = getAppDataDictionary(aliceGroup.groupContext.extensions)
const bobDictionary = getAppDataDictionary(bobGroup.groupContext.extensions)
```

## Notes

- **Component Id Range**: Use ids in the private use range (0x8000 - 0xFFFF) for application-defined components, like the application-specific proposal and extension type ranges.
- **Remove Operation**: An `app_data_update` proposal with `operation: "remove"` deletes a component's entry. Removing a component that has no entry is invalid.
- **Multiple Updates**: A commit may contain several update proposals for the same component; they are passed to the `appDataUpdateCallback` in commit order. For a given component, a commit must contain either a single remove or one or more updates — never both.
- **Custom Application Logic**: Override `appDataUpdateCallback` in the `ClientConfig` to implement diff-based or merge semantics for update payloads. Every member must use the same logic, since the resulting dictionary feeds the confirmation tag.
- **No UpdatePath Required**: Unlike `group_context_extensions` proposals, `app_data_update` proposals do not force an UpdatePath, making dictionary updates cheap.
- **Interaction with GroupContextExtensions**: A commit may combine a `group_context_extensions` proposal with `app_data_update` proposals, but the GCE proposal must come first. When the group's required capabilities include the `app_data_update` proposal type, a GCE proposal must not add, remove, or modify the `app_data_dictionary` extension.
