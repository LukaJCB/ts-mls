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
  generateKeyPackage,
  defaultCapabilities,
  defaultLifetime,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  createCommit,
  Proposal,
  emptyPskIndex,
  joinGroup,
  joinGroupExternal,
  processPrivateMessage,
  processPublicMessage,
  createGroupInfoWithExternalPubAndRatchetTree,
  makePskIndex,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)
const groupId = new TextEncoder().encode("group1")

// Alice creates the group, this is epoch 0
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)
const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

// Alice adds Bob and commits, this is epoch 1
const addBobProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: bob.publicPackage },
}
const addBobCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)
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

// Alice creates GroupInfo with external public key and ratchet tree extensions and sends it to Charlie
const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)

// Charlie joins externally using GroupInfo and creates an external commit (epoch 2)
const charlieJoinGroupCommitResult = await joinGroupExternal(
  groupInfo,
  charlie.publicPackage,
  charlie.privatePackage,
  false,
  impl,
)
let charlieGroup = charlieJoinGroupCommitResult.newState

// All members process the external join commit to update their state (epoch 2)
const aliceProcessCharlieJoinResult = await processPublicMessage(
  aliceGroup,
  charlieJoinGroupCommitResult.publicMessage,
  makePskIndex(aliceGroup, {}),
  impl,
)

aliceGroup = aliceProcessCharlieJoinResult.newState

const bobProcessCharlieJoinResult = await processPublicMessage(
  bobGroup,
  charlieJoinGroupCommitResult.publicMessage,
  makePskIndex(bobGroup, {}),
  impl,
)

bobGroup = bobProcessCharlieJoinResult.newState
```

---

### What to Expect

- After running this scenario, Alice, Bob, and Charlie will all be members of the group and share the same group state at epoch 1.
- Charlie is able to join the group externally using the GroupInfo and the contained ratchet tree and external public key.
