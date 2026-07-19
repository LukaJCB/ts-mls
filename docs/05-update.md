# Update

This scenario demonstrates how group members can update their own keys with an empty commit. It shows how members can refresh their key material and how the group state advances epochs even when no proposals are included in a commit.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group (epoch 0).
2. **Adding Bob**: Alice adds Bob to the group with an Add proposal and Commit (epoch 1).
3. **Bob Joins**: Bob joins the group using the Welcome message (epoch 1).
4. **Alice Updates**: Alice updates her own key with an empty commit (epoch 2).
5. **Bob Processes Alice's Update**: Bob processes the update commit and advances to epoch 2.
6. **Bob Updates**: Bob updates his own key with an empty commit (epoch 3).
7. **Alice Processes Bob's Update**: Alice processes the update commit and advances to epoch 3.
8. **Alice Proposes an Update**: Alice submits an Update Proposal
9. **Bob Commits to Alice's Update**: Bob commits to Alice's updated key and advances to epoch 4.
10. **Alice Processes Bob's Commit**: Alice processes the update commit and advances to epoch 4.

## Key Concepts

- **Empty Commit**: A commit with no proposals, used to refresh a member's key material and advance the group epoch.
- **LeafNode patch**: A LeafNode patch can be sent as part of a commit or an Update Proposal to update one's own credential, signature key, LeafNodeExtensions or capabilities.
- **Key Rotation**: Regular updates help maintain forward secrecy and post-compromise security.
- **Update Proposal**: An MLS Proposal that allows a member to propose to update their keys without having to create a commit themselves.

---

```typescript
import {
  createCommit,
  Credential,
  defaultCapabilities,
  defaultCredentialTypes,
  defaultExtensionTypes,
  createGroup,
  createUpdateProposal,
  generateSignatureKeyPair,
  joinGroup,
  processMessage,
  processKeyPackage,
  getCiphersuiteImpl,
  generateKeyPackage,
  Proposal,
  leafNodeSources,
  unsafeTestingAuthenticationService,
  updateLeafKey,
  wireformats,
  zeroOutUint8Array,
} from "ts-mls"

const impl = await getCiphersuiteImpl("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
const groupId = new TextEncoder().encode("group1")

// Alice creates the group, this is epoch 0
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})

const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })

// Alice adds Bob and commits, this is epoch 1
const addBobProposal: Proposal = await processKeyPackage({ context, state: aliceGroup, keyPackage: bob.publicPackage })
const addBobCommitResult = await createCommit({
  context,
  state: aliceGroup,
  extraProposals: [addBobProposal],
})
aliceGroup = addBobCommitResult.newState
addBobCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob joins the group, he is now also in epoch 1
let bobGroup = await joinGroup({
  context,
  welcome: addBobCommitResult.welcome!.welcome,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Alice updates her key with an empty commit, transitioning to epoch 2
const emptyCommitResult = await createCommit({
  context,
  state: aliceGroup,
})
aliceGroup = emptyCommitResult.newState
emptyCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob processes Alice's update and transitions to epoch 2
const bobProcessCommitResult = await processMessage({
  context,
  state: bobGroup,
  message: emptyCommitResult.commit,
})
bobGroup = bobProcessCommitResult.newState
bobProcessCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob creates a LeafNodePatch to update his credential and capabilities
const bobLeafNodePatch = {
  credential: {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bobby"),
  },
  capabilities: { ...defaultCapabilities(), extensions: [0xf000] },
}

// Bob updates his key with an empty commit and includes the leafNode patch, transitioning to epoch 3
const emptyCommitResult3 = await createCommit({
  context,
  state: aliceGroup,
  leafNodePatch: bobLeafNodePatch,
})
bobGroup = emptyCommitResult3.newState
emptyCommitResult3.consumed.forEach(zeroOutUint8Array)

// Alice processes Bob's update and transitions to epoch 3
const aliceProcessCommitResult3 = await processMessage({
  context,
  state: aliceGroup,
  message: emptyCommitResult3.commit,
})
aliceGroup = aliceProcessCommitResult3.newState
aliceProcessCommitResult3.consumed.forEach(zeroOutUint8Array)

// Alice creates a new signature key pair
const aliceNewSignatureKeys = await generateSignatureKeyPair(context.cipherSuite)

// Alice creates a leafNode patch to update her signature key and leafNodeExtensions
const aliceLeafNodePatch = {
  signatureKeyPair: aliceNewSignatureKeys,
  extensions: [
    {
      extensionType: defaultExtensionTypes.application_id,
      extensionData: new Uint8Array(42),
    },
  ],
}

// Alice creates a new KeyPackage and proposes to update her keys
const createProposalResult = await createUpdateProposal({
  context,
  state: aliceGroup,
  leafNodePatch: aliceLeafNodePatch,
})
aliceGroup = createProposalResult.newState
createProposalResult.consumed.forEach(zeroOutUint8Array)

// Bob receives and accepts Alice's proposal
const acceptProposalResult = await processMessage({ context, state: bobGroup, message: createProposalResult.message })
bobGroup = acceptProposalResult.newState
acceptProposalResult.consumed.forEach(zeroOutUint8Array)

// Bob commits to Alice's proposal and transitions to epoch 4
const updateBobCommitResult = await createCommit({
  context,
  state: bobGroup,
})
bobGroup = updateBobCommitResult.newState
updateBobCommitResult.consumed.forEach(zeroOutUint8Array)

// Alice updates her encryption keys to the ones in the proposal
aliceGroup = {
  ...aliceGroup,
  privatePath: updateLeafKey(aliceGroup.privatePath, createProposalResult.newLeafKeypair.hpkePrivateKey),
  signaturePrivateKey: aliceNewSignatureKeys.signKey,
}

// Alice processes Bob's commit and transitions to epoch 4
const aliceProcessCommitResult4 = await processMessage({
  context,
  state: aliceGroup,
  message: updateBobCommitResult.commit,
})
aliceGroup = aliceProcessCommitResult4.newState
aliceProcessCommitResult4.consumed.forEach(zeroOutUint8Array)
```

---

### What to Expect

- After running this scenario, both Alice and Bob will have rotated their keys and advanced the group epoch, even though no new members were added or removed.
- The group state remains synchronized, and both members benefit from improved forward secrecy.
