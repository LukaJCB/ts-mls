# Adding Multiple Members at Once

This scenario demonstrates how Alice creates a group and adds both Bob and Charlie in a single commit, allowing them to join at the same time. This approach is efficient for onboarding multiple new members and demonstrates how the group state and epoch are updated in a single operation.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group (epoch 0).
2. **Adding Bob and Charlie**: Alice adds both Bob and Charlie to the group with two Add proposals in a single Commit (epoch 1).
3. **Bob and Charlie Join**: Both Bob and Charlie join the group using the same Welcome message (epoch 1).

## Key Concepts

- **Multiple Proposals**: Multiple Add proposals can be included in a single commit, allowing several members to join at once.
- **Welcome Message**: A single Welcome message can be used by all new members added in the same commit.

---

```typescript
import {
  createGroup,
  Credential,
  defaultCredentialTypes,
  generateKeyPackage,
  defaultCapabilities,
  defaultLifetime,
  defaultProposalTypes,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  createCommit,
  Proposal,
  emptyPskIndex,
  joinGroup,
  processPrivateMessage,
  makePskIndex,
  unsafeTestingAuthenticationService,
  wireformats,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)
const groupId = new TextEncoder().encode("group1")

// Alice creates the group, this is epoch 0
let aliceGroup = await createGroup(
  groupId,
  alice.publicPackage,
  alice.privatePackage,
  [],
  unsafeTestingAuthenticationService,
  impl,
)

const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

const charlieCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("charlie"),
}
const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

// Alice adds Bob and Charlie in the same commit, transitioning to epoch 1
const addBobProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: bob.publicPackage },
}
const addCharlieProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: charlie.publicPackage },
}
const addCommitResult = await createCommit(
  { state: aliceGroup, cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  { extraProposals: [addBobProposal, addCharlieProposal] },
)
aliceGroup = addCommitResult.newState
if (addCommitResult.commit.wireformat !== wireformats.mls_private_message) throw new Error("Expected private message")

// Bob and Charlie join the group, both are now in epoch 1
let bobGroup = await joinGroup(
  addCommitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  unsafeTestingAuthenticationService,
  impl,
  aliceGroup.ratchetTree,
)
let charlieGroup = await joinGroup(
  addCommitResult.welcome!,
  charlie.publicPackage,
  charlie.privatePackage,
  emptyPskIndex,
  unsafeTestingAuthenticationService,
  impl,
  aliceGroup.ratchetTree,
)
```

---

### What to Expect

- After running this scenario, Alice, Bob, and Charlie will all be members of the group and share the same group state at epoch 1.
- Both Bob and Charlie use the same Welcome message to join, demonstrating efficient onboarding of multiple members.
