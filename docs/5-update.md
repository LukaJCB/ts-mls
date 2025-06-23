# Update

This scenario demonstrates how group members can update their own keys with an empty commit.

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

// Alice updates
const emptyCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [], impl)
if (emptyCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")
aliceGroup = emptyCommitResult.newState
const bobProcessCommitResult = await processPrivateMessage(
  bobGroup,
  emptyCommitResult.commit.privateMessage,
  makePskIndex(bobGroup, {}),
  impl,
)
bobGroup = bobProcessCommitResult.newState

// Bob updates
const emptyCommitResult3 = await createCommit(bobGroup, emptyPskIndex, false, [], impl)
if (emptyCommitResult3.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")
bobGroup = emptyCommitResult3.newState
const aliceProcessCommitResult3 = await processPrivateMessage(
  aliceGroup,
  emptyCommitResult3.commit.privateMessage,
  makePskIndex(aliceGroup, {}),
  impl,
)
aliceGroup = aliceProcessCommitResult3.newState
```
