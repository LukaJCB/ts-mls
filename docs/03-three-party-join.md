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
  defaultCredentialTypes,
  generateKeyPackage,
  defaultProposalTypes,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  createCommit,
  Proposal,
  joinGroup,
  processPrivateMessage,
  makePskIndex,
  unsafeTestingAuthenticationService,
  wireformats,
  zeroOutUint8Array,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
const groupId = new TextEncoder().encode("group1")

// Alice creates the group, this is epoch 0
let aliceGroup = await createGroup({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})

const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })

const charlieCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("charlie"),
}
const charlie = await generateKeyPackage({ credential: charlieCredential, cipherSuite: impl })

const addBobProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: bob.publicPackage },
}
// Alice adds Bob and commits, this is epoch 1
const addBobCommitResult = await createCommit({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  state: aliceGroup,
  extraProposals: [addBobProposal],
})

if (addBobCommitResult.commit.wireformat !== wireformats.mls_private_message)
  throw new Error("Expected private message")

aliceGroup = addBobCommitResult.newState
addBobCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob joins the group, he is now also in epoch 1
let bobGroup = await joinGroup({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  welcome: addBobCommitResult.welcome!.welcome,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

const addCharlieProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: charlie.publicPackage },
}
// Alice adds Charlie, transitioning into epoch 2
const addCharlieCommitResult = await createCommit({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  state: aliceGroup,
  extraProposals: [addCharlieProposal],
})
aliceGroup = addCharlieCommitResult.newState
addCharlieCommitResult.consumed.forEach(zeroOutUint8Array)
if (addCharlieCommitResult.commit.wireformat !== wireformats.mls_private_message)
  throw new Error("Expected private message")

// Bob processes the commit and transitions to epoch 2 as well
const processAddCharlieResult = await processPrivateMessage({
  context: {
    cipherSuite: impl,
    authService: unsafeTestingAuthenticationService,
    pskIndex: makePskIndex(bobGroup, {}),
  },
  state: bobGroup,
  privateMessage: addCharlieCommitResult.commit.privateMessage,
})
bobGroup = processAddCharlieResult.newState
processAddCharlieResult.consumed.forEach(zeroOutUint8Array)

// Charlie joins and is also in epoch 2
let charlieGroup = await joinGroup({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  welcome: addCharlieCommitResult.welcome!.welcome,
  keyPackage: charlie.publicPackage,
  privateKeys: charlie.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})
```

---

### What to Expect

- After running this scenario, Alice, Bob, and Charlie will all have a synchronized view of the group state.
- Each member will have processed the necessary commits to stay in sync.
- The group epoch will increment with each commit, reflecting the addition of new members.
