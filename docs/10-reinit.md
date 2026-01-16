# Resumption - Reinit (Reinitialization)

This scenario demonstrates how a group can be reinitialized with a new group ID and ciphersuite, and how members rejoin the new group. Reinitialization is used to start a new group with the same membership and different parameters, and linking it to the old group via a resumption PSK, for example, to upgrade the ciphersuite, extensions or MLS version.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group (epoch 0).
2. **Adding Bob**: Alice adds Bob to the group with an Add proposal and Commit (epoch 1).
3. **Bob Joins**: Bob joins the group using the Welcome message (epoch 1).
4. **Reinitialization Proposal**: Alice proposes to reinitialize the group with a new group ID and ciphersuite (epoch 2).
5. **Processing the Reinit Commit**: Bob processes the reinit commit and prepares to join the new group.
6. **New Key Packages**: Alice and Bob generate new key packages for the new group.
7. **Creating the New Group**: Alice creates the new group using the new parameters (epoch 0 of the new group).
8. **Bob Joins the New Group**: Bob joins the reinitialized group using the Welcome message.

## Key Concepts

- **Reinitialization (Reinit)**: The process of starting a new group with the same or similar membership, but with a new group ID, ciphersuite, and fresh cryptographic material.
- **Reinit Proposal/Commit**: A special commit that signals the intent to reinitialize the group. Members must process this commit and prepare to join the new group.
- **Key Package Rotation**: Members generate new key packages for the new group, providing fresh credentials and cryptographic context.

---

```typescript
import {
  createCommit,
  Credential,
  defaultCredentialTypes,
  createGroup,
  defaultProposalTypes,
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

// Alice creates the group (epoch 0)
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

// Alice adds Bob (epoch 1)
const addBobProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: bob.publicPackage },
}
const commitResult = await createCommit(
  { state: aliceGroup, cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  { extraProposals: [addBobProposal] },
)
aliceGroup = commitResult.newState

// Bob joins the group (epoch 1)
let bobGroup = await joinGroup(
  commitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  unsafeTestingAuthenticationService,
  impl,
  aliceGroup.ratchetTree,
)

// Alice proposes to reinitialize the group with a new group ID and ciphersuite
const newCiphersuite = "MLS_256_XWING_AES256GCM_SHA512_Ed25519" // or another supported ciphersuite
const newGroupId = new TextEncoder().encode("new-group1")
const reinitCommitResult = await reinitGroup(
  aliceGroup,
  newGroupId,
  "mls10",
  newCiphersuite,
  [],
  unsafeTestingAuthenticationService,
  impl,
)
aliceGroup = reinitCommitResult.newState

if (reinitCommitResult.commit.wireformat !== wireformats.mls_private_message)
  throw new Error("Expected private message")

// Bob processes the reinit commit and prepares to join the new group
const processReinitResult = await processPrivateMessage(
  bobGroup,
  reinitCommitResult.commit.privateMessage,
  makePskIndex(bobGroup, {}),
  unsafeTestingAuthenticationService,
  impl,
)
bobGroup = processReinitResult.newState

// Alice and Bob generate new key packages for the new group
const newImpl = await getCiphersuiteImpl(getCiphersuiteFromName(newCiphersuite))
const bobNewKeyPackage = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], newImpl)
const aliceNewKeyPackage = await generateKeyPackage(
  aliceCredential,
  defaultCapabilities(),
  defaultLifetime,
  [],
  newImpl,
)

// Alice creates the new group using the new parameters
const resumeGroupResult = await reinitCreateNewGroup(
  aliceGroup,
  aliceNewKeyPackage.publicPackage,
  aliceNewKeyPackage.privatePackage,
  [bobNewKeyPackage.publicPackage],
  newGroupId,
  newCiphersuite,
  [],
  unsafeTestingAuthenticationService,
)
aliceGroup = resumeGroupResult.newState

// Bob joins the reinitialized group using the Welcome message
bobGroup = await joinGroupFromReinit(
  bobGroup,
  resumeGroupResult.welcome!,
  bobNewKeyPackage.publicPackage,
  bobNewKeyPackage.privatePackage,
  unsafeTestingAuthenticationService,
  aliceGroup.ratchetTree,
)
```

---

## What to Expect

- After running this scenario, Alice and Bob will both be members of the reinitialized group, sharing the same group state at epoch 0 of the new group.
- The group will have a new group ID, a new ciphersuite, and fresh cryptographic context, providing forward secrecy and enabling upgrades or migrations.
