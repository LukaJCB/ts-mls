# External Join

This scenario demonstrates how a new member can join a group externally using a GroupInfo object.

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
  createGroupInfoWithExternalPub,
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
aliceGroup = addBobCommitResult.newState
let bobGroup = await joinGroup(
  addBobCommitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

// Alice creates groupInfo and sends it to Charlie
const groupInfo = await createGroupInfoWithExternalPub(aliceGroup, impl)

// Charlie joins externally
const charlieJoinGroupCommitResult = await joinGroupExternal(
  groupInfo,
  charlie.publicPackage,
  charlie.privatePackage,
  aliceGroup.ratchetTree,
  false,
  impl,
)
let charlieGroup = charlieJoinGroupCommitResult.newState

// All members process the external join
aliceGroup = await processPublicMessage(
  aliceGroup,
  charlieJoinGroupCommitResult.publicMessage,
  makePskIndex(aliceGroup, {}),
  impl,
)
bobGroup = await processPublicMessage(
  bobGroup,
  charlieJoinGroupCommitResult.publicMessage,
  makePskIndex(bobGroup, {}),
  impl,
)
```
