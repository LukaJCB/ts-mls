# External PSK

This scenario demonstrates how to use an external pre-shared key (PSK) in a group commit.

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
  bytesToBase64,
} from "ts-mls"

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
const addBobCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)
aliceGroup = addBobCommitResult.newState

let bobGroup = await joinGroup(
  addBobCommitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

const pskSecret = impl.rng.randomBytes(impl.kdf.size)
const pskNonce = impl.rng.randomBytes(impl.kdf.size)

const pskId = new TextEncoder().encode("psk-1")

const pskProposal: Proposal = {
  proposalType: "psk",
  psk: {
    preSharedKeyId: {
      psktype: "external",
      pskId,
      pskNonce,
    },
  },
}

const base64PskId = bytesToBase64(pskId)

const sharedPsks = { [base64PskId]: pskSecret }

// alice commits with the psk proposal
const pskCommitResult = await createCommit(aliceGroup, makePskIndex(aliceGroup, sharedPsks), false, [pskProposal], impl)

aliceGroup = pskCommitResult.newState

if (pskCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

// Bob processes the commit using the PSK
const processPskResult = await processPrivateMessage(
  bobGroup,
  pskCommitResult.commit.privateMessage,
  makePskIndex(bobGroup, sharedPsks),
  impl,
)

bobGroup = processPskResult.newState
```

It's also possible to use an external PSK when inviting a new member to the group, that new member will have to use the PSK when joining.

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
  bytesToBase64,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)
const groupId = new TextEncoder().encode("group1")
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

// Prepare external PSK
const pskSecret = impl.rng.randomBytes(impl.kdf.size)
const pskNonce = impl.rng.randomBytes(impl.kdf.size)
const pskId = new TextEncoder().encode("psk-1")
const pskProposal: Proposal = {
  proposalType: "psk",
  psk: {
    preSharedKeyId: {
      psktype: "external",
      pskId,
      pskNonce,
    },
  },
}
const base64PskId = bytesToBase64(pskId)
const sharedPsks = { [base64PskId]: pskSecret }

// Add Bob and use PSK in the same commit
const addBobProposal: Proposal = {
  proposalType: "add",
  add: { keyPackage: bob.publicPackage },
}
const commitResult = await createCommit(
  aliceGroup,
  makePskIndex(aliceGroup, sharedPsks),
  false,
  [addBobProposal, pskProposal],
  impl,
)
aliceGroup = commitResult.newState
let bobGroup = await joinGroup(
  commitResult.welcome!,
  bob.publicPackage,
  bob.privatePackage,
  makePskIndex(undefined, sharedPsks),
  impl,
  aliceGroup.ratchetTree,
)
```
