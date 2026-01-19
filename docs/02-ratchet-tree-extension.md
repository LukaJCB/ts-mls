# Ratchet Tree Extension

This scenario demonstrates how to use the Ratchet Tree Extension in MLS, which allows the group state (the ratchet tree) to be sent in the Welcome message. This is useful for new members joining a group, as it allows them to reconstruct the group state without needing to receive the full tree out-of-band.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group.
2. **Adding a Member with Ratchet Tree Extension**: Alice adds Bob to the group, including the ratchet tree in the Welcome message.
3. **Joining**: Bob joins the group using the Welcome message and does not need to provide a ratchet tree.

## Key Concepts

- **Ratchet Tree**: The data structure that represents the group state and cryptographic relationships between members.
- **Ratchet Tree Extension**: An extension that allows the full ratchet tree to be sent in the Welcome message, simplifying the join process for new members.
- **Welcome Message**: Contains the secrets and (optionally) the ratchet tree needed for a new member to join the group.

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
  joinGroup,
  makePskIndex,
  processPrivateMessage,
  createCommit,
  Proposal,
  unsafeTestingAuthenticationService,
  zeroOutUint8Array,
} from "ts-mls"

// Setup ciphersuite and credentials
const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
const groupId = new TextEncoder().encode("group1")

// Alice creates the group
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

const addBobProposal: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: { keyPackage: bob.publicPackage },
}

// Alice adds Bob with the ratchetTreeExtension = true
const commitResult = await createCommit({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  state: aliceGroup,
  extraProposals: [addBobProposal],
  ratchetTreeExtension: true,
})
aliceGroup = commitResult.newState
commitResult.consumed.forEach(zeroOutUint8Array)

// Bob joins using the welcome message and does not need to provide a ratchetTree
let bobGroup = await joinGroup({
  context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
  welcome: commitResult.welcome!,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
})
```

---

### What to Expect

- The ratchet tree is included in the Welcome message, so Bob can join the group without needing the tree out-of-band.
- Both Alice and Bob will have a synchronized view of the group state after Bob joins.
