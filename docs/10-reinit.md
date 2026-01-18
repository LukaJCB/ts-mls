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
  unsafeTestingAuthenticationService,
  wireformats,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
const groupId = new TextEncoder().encode("group1")

// Alice creates the group (epoch 0)
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

// Alice adds Bob (epoch 1)
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

// Bob joins the group (epoch 1)
let bobGroup = await joinGroup({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  welcome: commitResult.welcome!,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Alice proposes to reinitialize the group with a new group ID and ciphersuite
const newCiphersuite = "MLS_256_XWING_AES256GCM_SHA512_Ed25519" // or another supported ciphersuite
const newGroupId = new TextEncoder().encode("new-group1")
const reinitCommitResult = await reinitGroup({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  state: aliceGroup,
  groupId: newGroupId,
  version: "mls10",
  cipherSuite: newCiphersuite,
})
aliceGroup = reinitCommitResult.newState

if (reinitCommitResult.commit.wireformat !== wireformats.mls_private_message)
  throw new Error("Expected private message")

// Bob processes the reinit commit and prepares to join the new group
const processReinitResult = await processPrivateMessage({
  context: {
    cipherSuite: impl,
    authService: unsafeTestingAuthenticationService,
    pskIndex: makePskIndex(bobGroup, {}),
  },
  state: bobGroup,
  privateMessage: reinitCommitResult.commit.privateMessage,
})
bobGroup = processReinitResult.newState

// Alice and Bob generate new key packages for the new group
const newImpl = await getCiphersuiteImpl(getCiphersuiteFromName(newCiphersuite))
const bobNewKeyPackage = await generateKeyPackage({ credential: bobCredential, cipherSuite: newImpl })
const aliceNewKeyPackage = await generateKeyPackage({ credential: aliceCredential, cipherSuite: newImpl })

// Alice creates the new group using the new parameters
const resumeGroupResult = await reinitCreateNewGroup({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  state: aliceGroup,
  keyPackage: aliceNewKeyPackage.publicPackage,
  privateKeyPackage: aliceNewKeyPackage.privatePackage,
  memberKeyPackages: [bobNewKeyPackage.publicPackage],
  groupId: newGroupId,
  cipherSuite: newCiphersuite,
})
aliceGroup = resumeGroupResult.newState

// Bob joins the reinitialized group using the Welcome message
bobGroup = await joinGroupFromReinit({
  context: { cipherSuite: newImpl, authService: unsafeTestingAuthenticationService },
  suspendedState: bobGroup,
  welcome: resumeGroupResult.welcome!,
  keyPackage: bobNewKeyPackage.publicPackage,
  privateKeyPackage: bobNewKeyPackage.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})
```

---

## What to Expect

- After running this scenario, Alice and Bob will both be members of the reinitialized group, sharing the same group state at epoch 0 of the new group.
- The group will have a new group ID, a new ciphersuite, and fresh cryptographic context, providing forward secrecy and enabling upgrades or migrations.
