# Basic functionality

This scenario demonstrates how Alice creates a group and adds Bob, then they exchange messages securely.

```typescript
import {
  createGroup,
  Credential,
  generateKeyPackage,
  defaultCapabilities,
  defaultLifetime,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  emptyPskIndex,
  joinGroup,
  makePskIndex,
  processPrivateMessage,
  createApplicationMessage,
  createCommit,
  Proposal,
} from "ts-mls"

// Setup ciphersuite and credentials
const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)
const groupId = new TextEncoder().encode("group1")

// Alice creates the group
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

const addBobProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: bob.publicPackage },
}

// Alice adds Bob with the ratchetTreeExtension = true
const commitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl, true)
aliceGroup = commitResult.newState

// Bob joins using the welcome message and does not need to provide a ratchetTree
let bobGroup = await joinGroup(commitResult.welcome!, bob.publicPackage, bob.privatePackage, emptyPskIndex, impl)

// Alice sends a message to Bob
const messageToBob = new TextEncoder().encode("Hello bob!")
const aliceCreateMessageResult = await createApplicationMessage(aliceGroup, messageToBob, impl)
aliceGroup = aliceCreateMessageResult.newState

// Bob receives the message
const bobProcessMessageResult = await processPrivateMessage(
  bobGroup,
  aliceCreateMessageResult.privateMessage,
  makePskIndex(bobGroup, {}),
  impl,
)
bobGroup = bobProcessMessageResult.newState
```
