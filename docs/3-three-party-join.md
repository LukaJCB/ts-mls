# Three-Party Join

This scenario demonstrates how Alice creates a group, adds Bob, then adds Charlie, and all three can communicate securely.

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

const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities, defaultLifetime, [], impl)

// Alice adds Bob
const addBobProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: bob.publicPackage },
}
const addBobCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)

if (addBobCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

aliceGroup = addBobCommitResult.newState
let bobGroup = await joinGroup(
  addBobCommitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

// Bob processes the commit
const bobProcessCommitResult = await processPrivateMessage(
  bobGroup,
  addBobCommitResult.commit.privateMessage,
  makePskIndex(bobGroup, {}),
  impl,
)
bobGroup = bobProcessCommitResult.newState

// Alice adds Charlie
const addCharlieProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: charlie.publicPackage },
}
const addCharlieCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addCharlieProposal], impl)
aliceGroup = addCharlieCommitResult.newState
if (addCharlieCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")
const processAddCharlieResult = await processPrivateMessage(
  bobGroup,
  addCharlieCommitResult.commit.privateMessage,
  makePskIndex(bobGroup, {}),
  impl,
)
bobGroup = processAddCharlieResult.newState
let charlieGroup = await joinGroup(
  addCharlieCommitResult.welcome!,
  charlie.publicPackage,
  charlie.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

// Charlie processes the commit
const charlieProcessCommitResult = await processPrivateMessage(
  charlieGroup,
  addCharlieCommitResult.commit.privateMessage,
  makePskIndex(charlieGroup, {}),
  impl,
)
charlieGroup = charlieProcessCommitResult.newState
```
