# Client State Serialization

This scenario demonstrates how to serialize and deserialize client state to binary format. Serialization is essential for persisting group state to disk, databases, or transferring it across processes, allowing you to restore a client's MLS session later.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group.
2. **Serialization**: Serialize Alice's client state to binary format using `clientStateEncoder`.
3. **Deserialization**: Deserialize the binary data back to a client state using `clientStateDecoder`.

## Key Concepts

- **clientStateEncoder**: An encoder that converts a `ClientState` object to binary format (Uint8Array).
- **clientStateDecoder**: A decoder that converts binary data back to a `ClientState` object.
- **encode**: A utility function that applies an encoder to produce binary data.
- **decode**: A utility function that applies an decoder to read binary data.

---

```typescript
import {
  createGroup,
  createCommit,
  createApplicationMessage,
  Credential,
  defaultCredentialTypes,
  getCiphersuiteImpl,
  generateKeyPackage,
  Proposal,
  defaultProposalTypes,
  encode,
  decode,
  clientStateEncoder,
  clientStateDecoder,
  unsafeTestingAuthenticationService,
  zeroOutUint8Array,
} from "ts-mls"

// Setup ciphersuite
const impl = await getCiphersuiteImpl("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }

// Setup Alice's credential
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}

const alice = await generateKeyPackage({
  credential: aliceCredential,
  cipherSuite: impl,
})

const groupId = new TextEncoder().encode("test-group")

// Alice creates the group
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})

// Serialize the client state to binary
const binary = encode(clientStateEncoder, aliceGroup)

// Deserialize the binary data back to client state
const deserializedState = decode(clientStateDecoder, binary)

if (!deserializedState) {
  throw new Error("Binary deserialization failed unexpectedly")
}

aliceGroup = deserializedState

// Now let's evolve the state by adding a member
const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage({
  credential: bobCredential,
  cipherSuite: impl,
})

// Add Bob and Charlie in a single commit
const addBobCommitResult = await createCommit({
  context,
  state: aliceGroup,
  extraProposals: [
    {
      proposalType: defaultProposalTypes.add,
      add: {
        keyPackage: bob.publicPackage,
      },
    },
  ],
})

aliceGroup = addBobCommitResult.newState
addBobCommitResult.consumed.forEach(zeroOutUint8Array)
```

## Notes

- **Binary Format**: The serialized state is a `Uint8Array` that can be stored in files, databases, or transmitted over the network, it uses the [TLS presentation language](https://www.rfc-editor.org/rfc/rfc9420.html#RFC8446) that is found throughout the MLS protocol.
- **Decoder Return Value**: `decode` returns the `clientState` or `undefined` if decoding fails.
- **State Persistence**: Serialize state after significant operations to enable recovery from crashes or restarts.
- **Security Considerations**: Serialized state contains sensitive cryptographic material (private keys, secrets). Store it securely with appropriate encryption and access controls.
- **Full Fidelity**: Serialization preserves all aspects of the state including keys, proposals, epoch information, and tree structure.
- **Storage Best Practices**: Consider storing state after each epoch change to minimize potential data loss.
