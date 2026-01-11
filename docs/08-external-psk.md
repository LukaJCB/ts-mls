# External PSK

This scenario demonstrates how to use an external pre-shared key (PSK) in a group commit. External PSKs allow out-of-band secrets to be injected into the group key schedule, providing additional security.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group (epoch 0).
2. **Adding Bob**: Alice adds Bob to the group with an Add proposal and Commit (epoch 1).
3. **Bob Joins**: Bob joins the group using the Welcome message (epoch 1).
4. **External PSK Preparation**: Alice and Bob agree on an external PSK out-of-band.
5. **Committing with PSK**: Alice commits to the group using a PSK proposal (epoch 2).
6. **Bob Processes the Commit**: Bob processes the commit using the external PSK.

## Key Concepts

- **External PSK**: A pre-shared key that is not derived from group operations, but is provided out-of-band and referenced by a unique ID and nonce.
- **PSK Proposal**: A proposal to inject a PSK into the group key schedule, increasing entropy and enabling advanced scenarios.
- **PSK Index**: A mapping from PSK IDs to secrets, provided by each client when processing commits involving PSKs.

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
  bytesToBase64,
  pskTypes,
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
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

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
const addBobCommitResult = await createCommit(
  { state: aliceGroup, cipherSuite: impl },
  { extraProposals: [addBobProposal] },
)
aliceGroup = addBobCommitResult.newState

// Bob joins the group (epoch 1)
let bobGroup = await joinGroup(
  addBobCommitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

// Prepare an external PSK and share it out-of-band
const pskSecret = impl.rng.randomBytes(impl.kdf.size)
const pskNonce = impl.rng.randomBytes(impl.kdf.size)
const pskId = new TextEncoder().encode("psk-1")

const pskProposal: Proposal = {
  proposalType: defaultProposalTypes.psk,
  psk: {
    preSharedKeyId: {
      psktype: pskTypes.external,
      pskId,
      pskNonce,
    },
  },
}

const base64PskId = bytesToBase64(pskId)
const sharedPsks = { [base64PskId]: pskSecret }

// Alice commits with the PSK proposal (epoch 2)
const pskCommitResult = await createCommit(
  {
    state: aliceGroup,
    cipherSuite: impl,
    pskIndex: makePskIndex(aliceGroup, sharedPsks),
  },
  { extraProposals: [pskProposal] },
)
aliceGroup = pskCommitResult.newState

if (pskCommitResult.commit.wireformat !== wireformats.mls_private_message) throw new Error("Expected private message")

// Bob processes the commit using the PSK
const processPskResult = await processPrivateMessage(
  bobGroup,
  pskCommitResult.commit.privateMessage,
  makePskIndex(bobGroup, sharedPsks),
  impl,
)
bobGroup = processPskResult.newState
```

---

### What to Expect

- After running this scenario, Alice and Bob will both be members of the group and share the same group state at epoch 2.
- The group key schedule will have incorporated the external PSK, increasing entropy.

---

## Using an External PSK When Inviting a New Member

It's also possible to use an external PSK when inviting a new member to the group. In this case, the new member must use the PSK when joining.

### Steps Covered

1. **Group Creation**: Alice creates a new MLS group (epoch 0).
2. **External PSK Preparation**: Alice and Bob agree on an external PSK out-of-band.
3. **Adding Bob and PSK**: Alice adds Bob and includes a PSK proposal in the same commit (epoch 1).
4. **Bob Joins with PSK**: Bob joins the group using the Welcome message and the external PSK (epoch 1).

### Key Concepts

- **Simultaneous Add and PSK**: A commit can add a new member and inject a PSK at the same time.
- **PSK Required for Join**: The new member must provide the correct PSK to join the group successfully.

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
  bytesToBase64,
  pskTypes,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)
const groupId = new TextEncoder().encode("group1")

// Alice creates the group (epoch 0)
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

// Prepare external PSK and share it out-of-band
const pskSecret = impl.rng.randomBytes(impl.kdf.size)
const pskNonce = impl.rng.randomBytes(impl.kdf.size)
const pskId = new TextEncoder().encode("psk-1")
const pskProposal: Proposal = {
  proposalType: defaultProposalTypes.psk,
  psk: {
    preSharedKeyId: {
      psktype: pskTypes.external,
      pskId,
      pskNonce,
    },
  },
}
const base64PskId = bytesToBase64(pskId)
const sharedPsks = { [base64PskId]: pskSecret }

// Add Bob and use PSK in the same commit (epoch 1)
const addBobProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: bob.publicPackage },
}
const commitResult = await createCommit(
  {
    state: aliceGroup,
    cipherSuite: impl,
    pskIndex: makePskIndex(aliceGroup, sharedPsks),
  },
  { extraProposals: [addBobProposal, pskProposal] },
)
aliceGroup = commitResult.newState

// Bob joins using the Welcome message and the external PSK (epoch 1)
let bobGroup = await joinGroup(
  commitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  makePskIndex(undefined, sharedPsks),
  impl,
  aliceGroup.ratchetTree,
)
```

---

### What to Expect

- After running this scenario, Alice and Bob will both be members of the group and share the same group state at epoch 1.
- The group key schedule will have incorporated the external PSK, and Bob was required to provide it to join successfully.
