# Additional Authenticated Data (AAD)

This scenario demonstrates how to use Additional Authenticated Data (AAD) with MLS messages. AAD allows you to attach metadata to messages that is cryptographically authenticated but not encrypted, ensuring that it cannot be tampered with while remaining visible to all recipients.

## Steps Covered

1. **Group Setup**: Create a group with Alice and Bob.
2. **Application Message with AAD**: Send an application message with AAD and verify tampering is detected.
3. **Proposal with AAD**: Create a proposal with AAD and verify tampering protection.
4. **Commit with AAD**: Commit with AAD and verify tampering is detected.

## Key Concepts

- **Additional Authenticated Data (AAD)**: Data that is cryptographically authenticated but not encrypted, included in the authenticated portion of messages.
- **Tampering Protection**: Any modification to AAD will cause verification to fail, ensuring integrity.
- **Private Messages**: AAD is included in the AEAD encryption for private messages (application messages, private proposals/commits).
- **Public Messages**: AAD is included in the signature for public messages (public proposals/commits).
- **Accessing AAD**: When processing a message, the AAD is included in the result object as the `aad` field, allowing recipients to read the authenticated metadata.

---

```typescript
import {
  createGroup,
  joinGroup,
  createCommit,
  createApplicationMessage,
  createProposal,
  processMessage,
  processPrivateMessage,
  processPublicMessage,
  Credential,
  defaultCredentialTypes,
  getCiphersuiteImpl,
  generateKeyPackage,
  Proposal,
  defaultProposalTypes,
  Capabilities,
  defaultCapabilities,
  protocolVersions,
  ciphersuites,
  wireformats,
  unsafeTestingAuthenticationService,
  CryptoError,
  CryptoVerificationError,
  zeroOutUint8Array,
} from "ts-mls"

// Setup ciphersuite
const impl = await getCiphersuiteImpl("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
const encoder = new TextEncoder()

const base = defaultCapabilities()
const capabilities: Capabilities = defaultCapabilities()

// Setup credentials
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: encoder.encode("alice"),
}
const alice = await generateKeyPackage({
  credential: aliceCredential,
  capabilities,
  cipherSuite: impl,
})

const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: encoder.encode("bob"),
}
const bob = await generateKeyPackage({
  credential: bobCredential,
  capabilities,
  cipherSuite: impl,
})

const groupId = encoder.encode("group1")

// Alice creates the group
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})

// Add Bob to the group
const addBobCommitResult = await createCommit({
  context,
  state: aliceGroup,
  extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
})

aliceGroup = addBobCommitResult.newState
addBobCommitResult.consumed.forEach(zeroOutUint8Array)

let bobGroup = await joinGroup({
  context,
  welcome: addBobCommitResult.welcome!.welcome,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Alice sends an application message with AAD
const appAuthenticatedData = encoder.encode("aad-app")
const appMessage = encoder.encode("hello bob")

const aliceAppResult = await createApplicationMessage({
  context,
  state: aliceGroup,
  message: appMessage,
  authenticatedData: appAuthenticatedData,
})
aliceGroup = aliceAppResult.newState
aliceAppResult.consumed.forEach(zeroOutUint8Array)

// Bob processes the valid message
const bobAppResult = await processMessage({
  context,
  state: bobGroup,
  message: aliceAppResult.message,
})

if (bobAppResult.kind === "applicationMessage") {
  // Access the AAD from the result
  console.log(`✓ AAD: "${new TextDecoder().decode(bobAppResult.aad)}"`)

  bobGroup = bobAppResult.newState
  bobAppResult.consumed.forEach(zeroOutUint8Array)
}

// Alice creates a public commit with AAD
const publicCommitAuthenticatedData = encoder.encode("aad-commit-public")

const alicePublicCommitResult = await createCommit({
  context,
  state: aliceGroup,
  wireAsPublicMessage: true,
  authenticatedData: publicCommitAuthenticatedData,
})

aliceGroup = alicePublicCommitResult.newState
alicePublicCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob processes the valid public commit
const bobProcessPublicCommitResult = await processMessage({
  context,
  state: bobGroup,
  message: alicePublicCommitResult.commit,
  callback: () => "accept",
})

// Access the AAD from the result
console.log(`✓ Public commit AAD: "${new TextDecoder().decode(bobProcessPublicCommitResult.aad)}"`)

bobGroup = bobProcessPublicCommitResult.newState
bobProcessPublicCommitResult.consumed.forEach(zeroOutUint8Array)
```

## Notes

- **Not Encrypted**: AAD is visible to anyone who can see the message (it's not encrypted), but it cannot be modified without detection.
- **Reading AAD**: When processing a message, the AAD is available in the result object's `aad` field (for both `processMessage`, `processPrivateMessage`, and `processPublicMessage`).
- **Private vs Public Messages**:
  - For private messages, AAD is included in the AEAD encryption operation
  - For public messages, AAD is included in the signature
- **Optional Parameter**: The `authenticatedData` parameter is optional in `createApplicationMessage`, `createProposal`, and `createCommit`.
- **Use Cases**:
  - Message IDs or sequence numbers
  - Timestamps
  - Delivery receipts or acknowledgments
  - Application-specific context or metadata
  - Routing information
  - Message priorities or flags
- **Access**: Recipients can read AAD but cannot modify it without breaking authentication.
- **Size Considerations**: While AAD isn't encrypted, it still adds to message size, so keep it reasonably small.
- **Error Types**: Tampering with AAD causes:
  - `CryptoError` for private messages (AEAD decryption fails)
  - `CryptoVerificationError` for public messages (signature verification fails)
