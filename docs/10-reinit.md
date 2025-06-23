# Reinit (Reinitialization)

This scenario demonstrates how a group can be reinitialized with a new group ID and ciphersuite, and how members rejoin the new group.

```typescript
import {
  createCommit,
  Credential,
  createGroup,
  emptyPskIndex,
  joinGroup,
  joinGroupFromReinit,
  makePskIndex,
  processPrivateMessage,
  reinitCreateNewGroup,
  reinitGroup,
  Proposal,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  generateKeyPackage,
  defaultCapabilities,
  defaultLifetime,
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
const commitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)
aliceGroup = commitResult.newState
let bobGroup = await joinGroup(
  commitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

// Reinitialize the group
const newCiphersuite = "MLS_256_XWING_AES256GCM_SHA512_Ed25519" // or another supported ciphersuite
const newGroupId = new TextEncoder().encode("new-group1")
const reinitCommitResult = await reinitGroup(aliceGroup, newGroupId, "mls10", newCiphersuite, [], impl)
aliceGroup = reinitCommitResult.newState

if (reinitCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

const processReinitResult = await processPrivateMessage(
  bobGroup,
  reinitCommitResult.commit.privateMessage,
  makePskIndex(bobGroup, {}),
  impl,
)
bobGroup = processReinitResult.newState

const newImpl = await getCiphersuiteImpl(getCiphersuiteFromName(newCiphersuite))
const bobNewKeyPackage = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], newImpl)
const aliceNewKeyPackage = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], newImpl)
const resumeGroupResult = await reinitCreateNewGroup(
  aliceGroup,
  aliceNewKeyPackage.publicPackage,
  aliceNewKeyPackage.privatePackage,
  [bobNewKeyPackage.publicPackage],
  newGroupId,
  newCiphersuite,
  [],
)
aliceGroup = resumeGroupResult.newState
bobGroup = await joinGroupFromReinit(
  bobGroup,
  resumeGroupResult.welcome!,
  bobNewKeyPackage.publicPackage,
  bobNewKeyPackage.privatePackage,
  aliceGroup.ratchetTree,
)
```
