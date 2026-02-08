# Group State Inspection and Key Reuse

This scenario demonstrates how to inspect the group state to retrieve information about members, access your own leaf node and signature keys, and how to reuse signature keys when generating multiple key packages. These utilities are useful for managing identity across multiple groups or key packages.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group.
2. **Adding Members**: Alice adds Bob and Charlie to the group.
3. **Members Join**: Bob and Charlie join the group.
4. **Inspect Group Members**: Use `getGroupMembers` to retrieve all members in the group.
5. **Access Own Leaf Node**: Use `getOwnLeafNode` to access your own leaf node information.
6. **Extract Signature Keys**: Use `getOwnSignatureKeyPair` to extract signature keys for reuse.
7. **Generate Key Package with Existing Keys**: Use `generateKeyPackageWithKey` to create a new key package with existing signature keys.

## Key Concepts

- **getGroupMembers**: Returns an array of all leaf nodes for current members in the group. Useful for inspecting member identities, credentials, and capabilities.
- **getOwnLeafNode**: Returns the leaf node for the current client, containing their credential, signature public key, and capabilities.
- **getOwnSignatureKeyPair**: Extracts both the signature private key and public key for the current client. This is useful for creating additional key packages with the same identity.
- **generateKeyPackageWithKey**: Creates a new key package using an existing signature key pair instead of generating a new one. This allows you to maintain the same signing identity across multiple key packages or groups.
- **LeafNode**: Contains member information including credential, signature public key, HPKE public key, capabilities, and extensions. Every time you create a KeyPackage, it will contain a LeafNode.

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
  generateKeyPackageWithKey,
  getGroupMembers,
  getOwnLeafNode,
  getOwnSignatureKeyPair,
  defaultProposalTypes,
  unsafeTestingAuthenticationService,
  LeafNode,
  zeroOutUint8Array,
} from "ts-mls"

// Setup ciphersuite
const impl = await getCiphersuiteImpl("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }

// Setup credentials
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({
  credential: aliceCredential,
  cipherSuite: impl,
})

const groupId = new TextEncoder().encode("group1")

// Alice creates the group
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})

// Setup Bob's credential
const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage({
  credential: bobCredential,
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
let bobGroup = await joinGroup({
  context,
  welcome: addBobCommitResult.welcome!.welcome,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Inspect group members
const members = getGroupMembers(aliceGroup)
// Expected output: alice, bob

// Access own leaf node
const aliceLeaf = getOwnLeafNode(aliceGroup)

// Extract signature key pairs
const bobKeys = getOwnSignatureKeyPair(bobGroup)

// Bob wants to create a new key package for a different group but keep the same identity
const bobNewKeyPackage = await generateKeyPackageWithKey({
  credential: bobCredential,
  signatureKeyPair: bobKeys, // Reuse Bob's existing signature keys
  cipherSuite: impl,
})

// Bob can now use this new key package to join another group with the same identity
```

## Notes

- **getGroupMembers** returns all current members (not including blank or removed leaf nodes).
- **getOwnLeafNode** returns your own leaf node from the ratchet tree at your current leaf index.
- **getOwnSignatureKeyPair** provides both the private and public signature keys for creating new key packages.
- **generateKeyPackageWithKey** is useful when you want to maintain the same identity (signature keys) across multiple groups or key packages.
- Reusing signature keys means that signatures created in different contexts can be verified as coming from the same identity.
- Each key package should still have unique HPKE keys and init keys for security, which `generateKeyPackageWithKey` generates automatically.
