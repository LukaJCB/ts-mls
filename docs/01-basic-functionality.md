# Basic functionality

This scenario demonstrates the most fundamental workflow in MLS: creating a group, adding a member, and exchanging messages.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group.
2. **Adding a Member**: Alice adds Bob to the group using an Add proposal and a Commit.
3. **Joining**: Bob joins the group using the Welcome message.
4. **Messaging**: Alice sends an encrypted application message to Bob, and Bob decrypts it.
5. **Key Deletion**: After sending or receiving a message, Alice and Bob delete the keys for that message.

## Key Concepts

- **KeyPackage**: A bundle of cryptographic keys and credentials for a member. Each member must have a KeyPackage to join a group.
- **Proposal**: A request to change the group (e.g., add/remove a member). Proposals are collected and then committed.
- **Commit**: A message that applies proposals and advances the group state. Commits are signed and update the group epoch.
- **Welcome**: A message that allows new members to join the group securely. It contains the secrets needed to initialize their state.
- **Application Message**: An encrypted message sent within the group. Only current group members can decrypt these messages.
- **Deletion Schedule**: It is advisable to delete all security-sensitive values as soon as they are consumed, this includes all keys used to encrypt and decrypt messages. These keys should be used only once and the next message will be encrypted with a new key.

Note that Bob will have to receive the ratchet tree over a **secure** out-of-band channel from Alice. If you wish to include the ratchet tree in the welcome message, check out [how to use the ratchet_tree extension](02-ratchet-tree-extension.md).

---

```typescript
import {
  createGroup,
  Credential,
  defaultCredentialTypes,
  generateKeyPackage,
  defaultProposalTypes,
  getCiphersuiteImpl,
  joinGroup,
  processMessage,
  createApplicationMessage,
  createCommit,
  Proposal,
  unsafeTestingAuthenticationService,
  zeroOutUint8Array,
} from "ts-mls"

// Setup ciphersuite and credentials
const impl = await getCiphersuiteImpl("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
const groupId = new TextEncoder().encode("group1")
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})

const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })

// Alice adds Bob
const addBobProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: bob.publicPackage },
}
const commitResult = await createCommit({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  state: aliceGroup,
  extraProposals: [addBobProposal],
})
aliceGroup = commitResult.newState

// Alice deletes the keys used to encrypt the commit message
commitResult.consumed.forEach(zeroOutUint8Array)

// Bob joins using the welcome message
let bobGroup = await joinGroup({
  context,
  welcome: commitResult.welcome!.welcome,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Alice sends a message to Bob
const messageToBob = new TextEncoder().encode("Hello bob!")
const aliceCreateMessageResult = await createApplicationMessage({
  context,
  state: aliceGroup,
  message: messageToBob,
})
aliceGroup = aliceCreateMessageResult.newState

// Alice deletes the keys used to encrypt the application message
aliceCreateMessageResult.consumed.forEach(zeroOutUint8Array)

// Bob receives the message
const bobProcessMessageResult = await processMessage({
  context,
  state: bobGroup,
  message: aliceCreateMessageResult.message,
})
bobGroup = bobProcessMessageResult.newState

// Bob deletes the keys used to decrypt the application message
bobProcessMessageResult.consumed.forEach(zeroOutUint8Array)
```

---

### What to Expect

- After running this scenario, both Alice and Bob will have a synchronized view of the group state.
- Bob will be able to decrypt and read Alice's message.
- The group state (including epoch, tree, and secrets) will be updated for both members.
- Bob and Alice will be able to process or create the same message multiple times until they delete their consumed keys, at that point, the message will no longer encrypt or decrypt correctly.
- ts-mls generally prefers immutability, users of this library can expect that no function in the library will directly mutate any values passed to the function. However, care must be taken to clean up any sensitive values that may linger on in memory (especially for long running processes).
