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

## Key Concepts

- **Empty Commit**: A commit with no proposals, used to refresh a member's key material and advance the group epoch.
- **Key Rotation**: Regular updates help maintain forward secrecy and post-compromise security.

---

```typescript
import {
  createCommit,
  Credential,
  createGroup,
  emptyPskIndex,
  joinGroup,
  makePskIndex,
  processPrivateMessage,
  defaultCapabilities,
  defaultLifetime,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  generateKeyPackage,
  Proposal,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)
const groupId = new TextEncoder().encode("group1")

// Alice creates the group, this is epoch 0
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

// Alice adds Bob and commits, this is epoch 1
const addBobProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: bob.publicPackage },
}
const addBobCommitResult = await createCommit(
  { state: aliceGroup, cipherSuite: impl },
  { extraProposals: [addBobProposal] },
)
aliceGroup = addBobCommitResult.newState

// Bob joins the group, he is now also in epoch 1
let bobGroup = await joinGroup(
  addBobCommitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

// Alice updates her key with an empty commit, transitioning to epoch 2
const emptyCommitResult = await createCommit({ state: aliceGroup, cipherSuite: impl })
if (emptyCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")
aliceGroup = emptyCommitResult.newState

// Bob processes Alice's update and transitions to epoch 2
const bobProcessCommitResult = await processPrivateMessage(
  bobGroup,
  emptyCommitResult.commit.privateMessage,
  makePskIndex(bobGroup, {}),
  impl,
)
bobGroup = bobProcessCommitResult.newState

// Bob updates his key with an empty commit, transitioning to epoch 3
const emptyCommitResult3 = await createCommit({ state: aliceGroup, cipherSuite: impl })
if (emptyCommitResult3.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")
bobGroup = emptyCommitResult3.newState

// Alice processes Bob's update and transitions to epoch 3
const aliceProcessCommitResult3 = await processPrivateMessage(
  aliceGroup,
  emptyCommitResult3.commit.privateMessage,
  makePskIndex(aliceGroup, {}),
  impl,
)
aliceGroup = aliceProcessCommitResult3.newState
```

---

### What to Expect

- After running this scenario, both Alice and Bob will have rotated their keys and advanced the group epoch, even though no new members were added or removed.
- The group state remains synchronized, and both members benefit from improved forward secrecy.
