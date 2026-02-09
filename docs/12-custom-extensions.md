# Custom Extensions in Group Context

This scenario demonstrates how to use custom extensions in the `GroupContext` and how capability validation ensures that all members support the required extensions. Custom extensions allow applications to add their own data to the group state.

## Steps Covered

1. **Setup Custom Capabilities**: Define capabilities that include support for a custom extension type.
2. **Group Creation with Extensions**: Alice creates a new MLS group with a custom extension in the group context.
3. **Adding Bob**: Alice adds Bob (who supports the custom extension) to the group.
4. **Bob Joins**: Bob joins the group and can see the custom extension in the group context.
5. **Validation Check**: Alice attempts to add Charlie (who doesn't support the custom extension) and receives a validation error.

## Key Concepts

- **Custom Extensions**: Application-defined extensions that can be added to the group context. Custom extension types should use values in the application-specific range (0xF000-0xFFFF).
- **Capabilities**: Declares what extensions, credentials, proposals, versions, and ciphersuites a member supports.
- **Required Capabilities**: When a group uses custom extensions, all members must declare support for those extensions in their capabilities.
- **Validation**: The MLS protocol validates that new members support all required extensions before allowing them to join.
- **Group Context Extensions**: Extensions that are part of the group context and always visible to all members.

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
  GroupContextExtension,
  makeCustomExtension,
  protocolVersions,
  ciphersuites,
  defaultProposalTypes,
  unsafeTestingAuthenticationService,
  ValidationError,
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
const customExtension: GroupContextExtension = makeCustomExtension({
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

// Verify Bob can see the custom extension in the group context
const foundExtension = bobGroup.groupContext.extensions.find((e) => e.extensionType === customExtensionType)

// Charlie doesn't support the custom extension
const charlieCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("charlie"),
}
const charlie = await generateKeyPackage({
  credential: charlieCredential,
  cipherSuite: impl,
  // Note: no custom capabilities specified
})

// Attempting to add Charlie should fail validation
try {
  await createCommit({
    context,
    state: aliceGroup,
    extraProposals: [
      {
        proposalType: defaultProposalTypes.add,
        add: {
          keyPackage: charlie.publicPackage,
        },
      },
    ],
  })
} catch (error) {
  // Should throw ValidationError when adding member without required capabilities"
}
```

## Notes

- Custom extension types should be chosen from the application-specific range to avoid conflicts with standard MLS extensions.
- All members of a group must declare support for any custom extensions used in the group context.
- The MLS protocol automatically validates that new members have the required capabilities before allowing them to join.
- Custom extensions in the group context are visible to all members and persist across epoch changes.
- If you need to add a member that doesn't support a custom extension, you must first remove the extension from the group context using a `group_context_extensions` proposal.
