# Adding multiple members at once

This scenario demonstrates how Alice creates a group and adds both Bob and Charlie in a single commit, allowing them to join at the same time.

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

// Alice adds Bob and Charlie in the same commit
const addBobProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: bob.publicPackage },
}
const addCharlieProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: charlie.publicPackage },
}
const addCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal, addCharlieProposal], impl)
aliceGroup = addCommitResult.newState

if (addCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

let bobGroup = await joinGroup(
  addCommitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)
let charlieGroup = await joinGroup(
  addCommitResult.welcome!,
  charlie.publicPackage,
  charlie.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)
```
