# Resumption - Branching

This scenario demonstrates how to branch a group and resume with new key packages and a new group ID. Branching starts a new group with a subset of the original group's participants (with no effect on the original group).The new group is linked to the old group via a resumption PSK.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group (epoch 0).
2. **Adding Bob**: Alice adds Bob to the group with an Add proposal and Commit (epoch 1).
3. **Bob Joins**: Bob joins the group using the Welcome message (epoch 1).
4. **New Key Packages and Group ID**: Alice and Bob generate new key packages and agree on a new group ID.
5. **Branching the Group**: Alice creates a branch commit to resume the group with the new parameters (epoch 0 of the new group).
6. **Bob Joins the New Branch**: Bob joins the new group branch using the Welcome message.

## Key Concepts

- **Group Resumption/Branching**: The process of creating a new group state from an existing group, with new keys and a new group ID.
- **Key Package Rotation**: Members generate new key packages to use in the resumed group, providing fresh cryptographic material.
- **Branch Commit**: A special commit that creates a new group branch, optionally with a new group ID and new members.

---

```typescript
import {
  createGroup,
  Credential,
  defaultCredentialTypes,
  generateKeyPackage,
  defaultCapabilities,
  defaultLifetime,
  defaultProposalTypes,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  createCommit,
  Proposal,
  emptyPskIndex,
  joinGroup,
  processPrivateMessage,
  makePskIndex,
  joinGroupFromBranch,
  branchGroup,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)
const groupId = new TextEncoder().encode("group1")
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

// Alice adds Bob
const addBobProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: bob.publicPackage },
}
const addBobCommitResult = await createCommit(
  { state: aliceGroup, cipherSuite: impl },
  { extraProposals: [addBobProposal] },
)
aliceGroup = addBobCommitResult.newState
let bobGroup = await joinGroup(
  addBobCommitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

// Prepare new key packages and group ID
const bobNewKeyPackage = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)
const aliceNewKeyPackage = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)
const newGroupId = new TextEncoder().encode("new-group1")

// Alice branches the old group into a new one with new key packages and a new group id
const branchCommitResult = await branchGroup(
  aliceGroup,
  aliceNewKeyPackage.publicPackage,
  aliceNewKeyPackage.privatePackage,
  [bobNewKeyPackage.publicPackage],
  newGroupId,
  impl,
)
aliceGroup = branchCommitResult.newState

// Bob joins the branched group
bobGroup = await joinGroupFromBranch(
  bobGroup,
  branchCommitResult.welcome!,
  bobNewKeyPackage.publicPackage,
  bobNewKeyPackage.privatePackage,
  aliceGroup.ratchetTree,
  impl,
)
```

---

## What to Expect

- After running this scenario, Alice and Bob will both be members of the new group branch, sharing the same group state at epoch 0 of the new group.
- The group will have fresh credentials, a new group ID, and a new cryptographic context, providing forward secrecy.
