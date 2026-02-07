# External Join

This scenario demonstrates how a new member can join a group externally using a GroupInfo object. This mechanism can be used when the existing members don't have a KeyPackage for the new member, for example, in the case of an "open" group that can be joined by new members without asking permission from existing members.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group (epoch 0).
2. **Adding Bob**: Alice adds Bob to the group with an Add proposal and Commit (epoch 1).
3. **Bob Joins**: Bob joins the group using the Welcome message (epoch 1).
4. **Creating GroupInfo**: Alice creates a GroupInfo object and sends it to Charlie.
5. **Charlie Joins Externally**: Charlie joins the group externally using the GroupInfo and the current ratchet tree (epoch 2).
6. **All Members Process the External Join**: Alice and Bob process the external join commit to update their state.

## Key Concepts

- **External Join**: Allows a new member to join the group using a GroupInfo object, without being present for the original commit.
- **GroupInfo**: Contains the current group state and cryptographic information needed for an external join.
- **Ratchet Tree**: The current group ratchet tree is required for the external join.

---

```typescript
import {
  createGroup,
  Credential,
  defaultCredentialTypes,
  generateKeyPackage,
  defaultProposalTypes,
  getCiphersuiteImpl,
  createCommit,
  Proposal,
  joinGroup,
  joinGroupExternal,
  processPrivateMessage,
  processPublicMessage,
  createGroupInfoWithExternalPubAndRatchetTree,
  unsafeTestingAuthenticationService,
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
const charlieCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("charlie"),
}
const charlie = await generateKeyPackage({ credential: charlieCredential, cipherSuite: impl })

// Alice adds Bob and commits, this is epoch 1
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

// Bob joins the group, he is now also in epoch 1
let bobGroup = await joinGroup({
  context,
  welcome: addBobCommitResult.welcome!.welcome,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Alice creates GroupInfo with external public key and ratchet tree extensions and sends it to Charlie
const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)

// Charlie joins externally using GroupInfo and creates an external commit (epoch 2)
const charlieJoinGroupCommitResult = await joinGroupExternal({
  context,
  groupInfo,
  keyPackage: charlie.publicPackage,
  privateKeys: charlie.privatePackage,
  resync: false,
})
let charlieGroup = charlieJoinGroupCommitResult.newState

// All members process the external join commit to update their state (epoch 2)
const aliceProcessCharlieJoinResult = await processPublicMessage({
  context,
  state: aliceGroup,
  publicMessage: charlieJoinGroupCommitResult.publicMessage,
})

aliceGroup = aliceProcessCharlieJoinResult.newState
aliceProcessCharlieJoinResult.consumed.forEach(zeroOutUint8Array)

const bobProcessCharlieJoinResult = await processPublicMessage({
  context,
  state: bobGroup,
  publicMessage: charlieJoinGroupCommitResult.publicMessage,
})

bobGroup = bobProcessCharlieJoinResult.newState
bobProcessCharlieJoinResult.consumed.forEach(zeroOutUint8Array)
```

---

### What to Expect

- After running this scenario, Alice, Bob, and Charlie will all be members of the group and share the same group state at epoch 1.
- Charlie is able to join the group externally using the GroupInfo and the contained ratchet tree and external public key.
