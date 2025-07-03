# Three-Party Join

This scenario demonstrates a more advanced workflow in MLS: creating a group, adding two members (Bob and Charlie) in sequence, and ensuring all three can communicate securely. This example shows how group state is updated and synchronized as new members join and process commits.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group.
2. **Adding Bob**: Alice adds Bob to the group using an Add proposal and a Commit.
3. **Bob Joins**: Bob joins the group using the Welcome message.
4. **Adding Charlie**: Alice adds Charlie to the group with another Add proposal and Commit.
5. **Bob Processes Charlie's Addition**: Bob processes the commit to update his state.
6. **Charlie Joinst**: Charlie joins the group.

## Key Concepts

- **Sequential Additions**: Members can be added one after another, with each addition requiring a new commit and state update.
- **Welcome Message**: Each new member receives a Welcome message containing the secrets needed to join the group.
- **Commit Processing**: Existing members must process each commit to stay in sync with the group state.
- **Epoch**: The group advances its epoch with each commit, ensuring all members are on the same version of the group.

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
  createCommit,
  Proposal,
  emptyPskIndex,
  joinGroup,
  processPrivateMessage,
  makePskIndex,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)
const groupId = new TextEncoder().encode("group1")

// Alice creates the group, this is epoch 0
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

const addBobProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: bob.publicPackage },
}
// Alice adds Bob and commits, this is epoch 1
const addBobCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)

if (addBobCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

aliceGroup = addBobCommitResult.newState

// Bob joins the group, he is now also in epoch 1
let bobGroup = await joinGroup(
  addBobCommitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

const addCharlieProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: charlie.publicPackage },
}
// Alice adds Charlie, transitioning into epoch 2
const addCharlieCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addCharlieProposal], impl)
aliceGroup = addCharlieCommitResult.newState
if (addCharlieCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

// Bob processes the commit and transitions to epoch 2 as well
const processAddCharlieResult = await processPrivateMessage(
  bobGroup,
  addCharlieCommitResult.commit.privateMessage,
  makePskIndex(bobGroup, {}),
  impl,
)
bobGroup = processAddCharlieResult.newState

// Charlie joins and is also in epoch 2
let charlieGroup = await joinGroup(
  addCharlieCommitResult.welcome!,
  charlie.publicPackage,
  charlie.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)
```

---

### What to Expect

- After running this scenario, Alice, Bob, and Charlie will all have a synchronized view of the group state.
- Each member will have processed the necessary commits to stay in sync.
- The group epoch will increment with each commit, reflecting the addition of new members.
