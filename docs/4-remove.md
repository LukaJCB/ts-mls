# Remove

This scenario demonstrates how a member can be removed from a group and how the remaining members update their state.

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
  processPrivateMessage,
  makePskIndex,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)
const groupId = new TextEncoder().encode("group1")
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

// Alice adds Bob
const addBobProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: bob.publicPackage },
}
const addBobCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)
aliceGroup = addBobCommitResult.newState
let bobGroup = await joinGroup(
  addBobCommitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

// Alice removes Bob
const removeBobProposal: Proposal = {
  proposalType: "remove",
  remove: { removed: 1 },
}
const removeBobCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [removeBobProposal], impl)
aliceGroup = removeBobCommitResult.newState

if (removeBobCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

// Bob processes the removal
const bobProcessRemoveResult = await processPrivateMessage(
  bobGroup,
  removeBobCommitResult.commit.privateMessage,
  makePskIndex(bobGroup, {}),
  impl,
)
bobGroup = bobProcessRemoveResult.newState
```
