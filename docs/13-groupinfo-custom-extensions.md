# GroupInfo Custom Extensions

This scenario demonstrates how to create a group with custom extensions and how new members can access those extensions after joining. Custom extensions in the GroupInfo are visible to all members and allow you to include application-specific metadata in the group state.

## Steps Covered

1. **Setup Custom Capabilities**: Define capabilities that include support for custom extension types.
2. **Group Creation with Extensions**: Alice creates a new MLS group with a custom extension.
3. **Adding Bob**: Alice adds Bob (who supports the custom extension) to the group.
4. **Bob Joins and Reads Extension**: Bob joins the group and can read the custom extension from the GroupInfo.

## Key Concepts

- **GroupInfo**: An object that contains information about the current group state, including extensions, which is accessible to all group members.
- **Custom Extensions**: Application-defined extensions that can be added to the group. Custom extension types should use values in the application-specific range.
- **Capabilities**: Declares what extensions, credentials, proposals, versions, and ciphersuites a member supports. Members must support all extensions present in the group.
- **Group Info Extensions**: Extensions that are part of the group state and visible to all members through the GroupInfo.

---

```typescript
import {
  createGroup,
  joinGroup,
  createCommit,
  Credential,
  defaultCredentialTypes,
  getCiphersuiteImpl,
  generateKeyPackage,
  Capabilities,
  GroupInfoExtension,
  makeCustomExtension,
  protocolVersions,
  ciphersuites,
  defaultProposalTypes,
  unsafeTestingAuthenticationService,
  zeroOutUint8Array,
} from "ts-mls"

// Setup ciphersuite
const impl = await getCiphersuiteImpl("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }

// Define a custom extension type (using application-specific range)
const customExtensionType: number = 0xf000

// Define capabilities that include the custom extension
const capabilities: Capabilities = {
  extensions: [customExtensionType],
  credentials: [defaultCredentialTypes.basic],
  proposals: [],
  versions: [protocolVersions.mls10],
  ciphersuites: [ciphersuites["MLS_256_XWING_AES256GCM_SHA512_Ed25519"]],
}

// Setup Alice's credential with custom capabilities
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

// Create custom extension data
const extensionData = new TextEncoder().encode("custom extension data")

// Create the custom extension
const customExtension: GroupInfoExtension = makeCustomExtension({
  extensionType: customExtensionType,
  extensionData,
})

// Alice creates the group with the custom extension
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
  extensions: [customExtension],
})

// Setup Bob's credential with the same capabilities (supports custom extension)
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

// Bob joins the group
const bobGroup = await joinGroup({
  context,
  welcome: addBobCommitResult.welcome!.welcome,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Bob can now read the custom extension from the group context
const foundExtension = bobGroup.groupContext.extensions.find((e) => e.extensionType === customExtensionType)
```

## Notes

- Custom extension types should be chosen from the application-specific range (0xF000-0xFFFF) to avoid conflicts with standard or future standard MLS extensions.
- Unlike Group Context Extensions, not all members must declare support for the extensions in their capabilities before joining a group that uses them.
- Extensions are passed to new members through the Welcome message and new members can introspect them when joining.
- When creating a group with custom extensions, pass them in the `extensions` parameter of `createGroup`.
