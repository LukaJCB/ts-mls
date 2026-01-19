# Remove

This scenario demonstrates how a member can be removed from a group and how the remaining members update their state. It shows the group epoch transitions and how removal proposals and commits are processed.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group (epoch 0).
2. **Adding Bob**: Alice adds Bob to the group with an Add proposal and Commit (epoch 1).
3. **Bob Joins**: Bob joins the group using the Welcome message (epoch 1).
4. **Removing Bob**: Alice removes Bob from the group with a Remove proposal and Commit (epoch 2).
5. **Bob Processes Removal**: Bob processes the removal commit and is removed from the group (epoch 2).

## Key Concepts

- **Remove Proposal**: A proposal to remove a member from the group, identified by their leaf index.
- **Commit**: Applies the removal and advances the group epoch.
- **Welcome Message**: Used for joining, not for removal. Removed members do not receive a new Welcome.

---

```typescript
import {
  createGroup,
  Credential,
  defaultCredentialTypes,
  generateKeyPackage,
  defaultProposalTypes,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  createCommit,
  Proposal,
  joinGroup,
  processPrivateMessage,
  makePskIndex,
  unsafeTestingAuthenticationService,
  wireformats,
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

// Bob joins the group, he is now also in epoch 1
let bobGroup = await joinGroup({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  welcome: addBobCommitResult.welcome!,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Alice removes Bob, transitioning to epoch 2
const removeBobProposal: Proposal = {
  proposalType: defaultProposalTypes.remove,
  remove: { removed: 1 }, // Bob's leaf index
}
const removeBobCommitResult = await createCommit({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  state: aliceGroup,
  extraProposals: [removeBobProposal],
})
aliceGroup = removeBobCommitResult.newState
if (removeBobCommitResult.commit.wireformat !== wireformats.mls_private_message)
  throw new Error("Expected private message")

// Bob processes the removal and is removed from the group (epoch 2)
const bobProcessRemoveResult = await processPrivateMessage({
  context: {
    cipherSuite: impl,
    authService: unsafeTestingAuthenticationService,
    pskIndex: makePskIndex(bobGroup, {}),
  },
  state: bobGroup,
  privateMessage: removeBobCommitResult.commit.privateMessage,
})
bobGroup = bobProcessRemoveResult.newState
```

---

### What to Expect

- After running this scenario, Alice remains in the group, and Bob is removed.
- The group epoch increments with each commit, reflecting the addition and removal of members.
- Bob's state will indicate he is no longer a member after processing the removal commit.
