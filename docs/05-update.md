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
- **Key Rotation**: Regular updates help maintain forward secrecy and post-compromise security.
- **Update Proposal**: An MLS Proposal that allows a member to propose to update their keys without having to create a commit themselves.

---

```typescript
import {
  createCommit,
  Credential,
  defaultCredentialTypes,
  createGroup,
  joinGroup,
  makePskIndex,
  processPrivateMessage,
  defaultProposalTypes,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  generateKeyPackage,
  Proposal,
  leafNodeSources,
  unsafeTestingAuthenticationService,
  wireformats,
  zeroOutUint8Array,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
const groupId = new TextEncoder().encode("group1")

// Alice creates the group, this is epoch 0
let aliceGroup = await createGroup({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
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
const addBobProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: bob.publicPackage },
}
const addBobCommitResult = await createCommit({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  state: aliceGroup,
  extraProposals: [addBobProposal],
})
aliceGroup = addBobCommitResult.newState
addBobCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob joins the group, he is now also in epoch 1
let bobGroup = await joinGroup({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  welcome: addBobCommitResult.welcome!.welcome,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Alice updates her key with an empty commit, transitioning to epoch 2
const emptyCommitResult = await createCommit({
  context: {
    cipherSuite: impl,
    authService: unsafeTestingAuthenticationService,
  },
  state: aliceGroup,
})
if (emptyCommitResult.commit.wireformat !== wireformats.mls_private_message) throw new Error("Expected private message")
aliceGroup = emptyCommitResult.newState
emptyCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob processes Alice's update and transitions to epoch 2
const bobProcessCommitResult = await processPrivateMessage({
  context: {
    cipherSuite: impl,
    authService: unsafeTestingAuthenticationService,
    pskIndex: makePskIndex(bobGroup, {}),
  },
  state: bobGroup,
  privateMessage: emptyCommitResult.commit.privateMessage,
})
bobGroup = bobProcessCommitResult.newState
bobProcessCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob updates his key with an empty commit, transitioning to epoch 3
const emptyCommitResult3 = await createCommit({
  context: {
    cipherSuite: impl,
    authService: unsafeTestingAuthenticationService,
  },
  state: aliceGroup,
})
if (emptyCommitResult3.commit.wireformat !== wireformats.mls_private_message)
  throw new Error("Expected private message")
bobGroup = emptyCommitResult3.newState
emptyCommitResult3.consumed.forEach(zeroOutUint8Array)

// Alice processes Bob's update and transitions to epoch 3
const aliceProcessCommitResult3 = await processPrivateMessage({
  context: {
    cipherSuite: impl,
    authService: unsafeTestingAuthenticationService,
    pskIndex: makePskIndex(aliceGroup, {}),
  },
  state: aliceGroup,
  privateMessage: emptyCommitResult3.commit.privateMessage,
})
aliceGroup = aliceProcessCommitResult3.newState
aliceProcessCommitResult3.consumed.forEach(zeroOutUint8Array)

// Bob creates a new KeyPackage
const alice2 = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })

// Alice proposes to update her keys
const updateAliceProposal: Proposal = {
  proposalType: defaultProposalTypes.update,
  update: { leafNode: { ...alice2.publicPackage.leafNode, leafNodeSource: leafNodeSources.update } },
}

// Bob commits to Alice's proposal and transitions to epoch 4
const updateBobCommitResult = await createCommit({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  state: bobGroup,
  extraProposals: [updateAliceProposal],
})
if (updateBobCommitResult.commit.wireformat !== wireformats.mls_private_message)
  throw new Error("Expected private message")
bobGroup = updateBobCommitResult.newState
updateBobCommitResult.consumed.forEach(zeroOutUint8Array)

// Alice processes Bob's commit and transitions to epoch 4
const aliceProcessCommitResult4 = await processPrivateMessage({
  context: {
    cipherSuite: impl,
    authService: unsafeTestingAuthenticationService,
    pskIndex: makePskIndex(aliceGroup, {}),
  },
  state: aliceGroup,
  privateMessage: updateBobCommitResult.commit.privateMessage,
})
aliceGroup = aliceProcessCommitResult4.newState
aliceProcessCommitResult4.consumed.forEach(zeroOutUint8Array)
```

---

### What to Expect

- After running this scenario, both Alice and Bob will have rotated their keys and advanced the group epoch, even though no new members were added or removed.
- The group state remains synchronized, and both members benefit from improved forward secrecy.
