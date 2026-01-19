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
  defaultProposalTypes,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  createCommit,
  Proposal,
  joinGroup,
  processPrivateMessage,
  joinGroupFromBranch,
  branchGroup,
  unsafeTestingAuthenticationService,
  zeroOutUint8Array,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
const groupId = new TextEncoder().encode("group1")
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

// Alice adds Bob
const addBobProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: bob.publicPackage },
}
const addBobCommitResult = await createCommit({
  context,
  state: aliceGroup,
  extraProposals: [addBobProposal],
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

// Prepare new key packages and group ID
const bobNewKeyPackage = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })
const aliceNewKeyPackage = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
const newGroupId = new TextEncoder().encode("new-group1")

// Alice branches the old group into a new one with new key packages and a new group id
const branchCommitResult = await branchGroup({
  context,
  state: aliceGroup,
  keyPackage: aliceNewKeyPackage.publicPackage,
  privateKeyPackage: aliceNewKeyPackage.privatePackage,
  memberKeyPackages: [bobNewKeyPackage.publicPackage],
  newGroupId,
})
aliceGroup = branchCommitResult.newState
branchCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob joins the branched group
bobGroup = await joinGroupFromBranch({
  context,
  oldState: bobGroup,
  welcome: branchCommitResult.welcome!.welcome,
  keyPackage: bobNewKeyPackage.publicPackage,
  privateKeyPackage: bobNewKeyPackage.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})
```

---

## What to Expect

- After running this scenario, Alice and Bob will both be members of the new group branch, sharing the same group state at epoch 0 of the new group.
- The group will have fresh credentials, a new group ID, and a new cryptographic context, providing forward secrecy.
