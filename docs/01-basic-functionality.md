# Basic functionality

This scenario demonstrates the most fundamental workflow in MLS: creating a group, adding a member, and exchanging messages.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group.
2. **Adding a Member**: Alice adds Bob to the group using an Add proposal and a Commit.
3. **Joining**: Bob joins the group using the Welcome message.
4. **Messaging**: Alice sends an encrypted application message to Bob, and Bob decrypts it.

## Key Concepts

- **KeyPackage**: A bundle of cryptographic keys and credentials for a member. Each member must have a KeyPackage to join a group.
- **Proposal**: A request to change the group (e.g., add/remove a member). Proposals are collected and then committed.
- **Commit**: A message that applies proposals and advances the group state. Commits are signed and update the group epoch.
- **Welcome**: A message that allows new members to join the group securely. It contains the secrets needed to initialize their state.
- **Application Message**: An encrypted message sent within the group. Only current group members can decrypt these messages.

Note that Bob will have to receive the ratchet tree out-of-band from Alice, if you wish to include the ratchet tree in the welcome message, check out [how to use the ratchet_tree extension](02-ratchet-tree-extension.md).

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

// Bob joins using the welcome message
let bobGroup = await joinGroup(
  commitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

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

---

### What to Expect

- After running this scenario, both Alice and Bob will have a synchronized view of the group state.
- Bob will be able to decrypt and read Alice's message.
- The group state (including epoch, tree, and secrets) will be updated for both members.
