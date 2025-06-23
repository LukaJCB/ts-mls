# Resumption

This scenario demonstrates how to branch a group and resume with new key packages and a new group ID.

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
  joinGroupFromBranch,
  branchGroup,
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

// Prepare new key packages and group ID
const bobNewKeyPackage = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)
const aliceNewKeyPackage = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)
const newGroupId = new TextEncoder().encode("new-group1")
const branchCommitResult = await branchGroup(
  aliceGroup,
  aliceNewKeyPackage.publicPackage,
  aliceNewKeyPackage.privatePackage,
  [bobNewKeyPackage.publicPackage],
  newGroupId,
  impl,
)
aliceGroup = branchCommitResult.newState
bobGroup = await joinGroupFromBranch(
  bobGroup,
  branchCommitResult.welcome!,
  bobNewKeyPackage.publicPackage,
  bobNewKeyPackage.privatePackage,
  aliceGroup.ratchetTree,
  impl,
)
```
