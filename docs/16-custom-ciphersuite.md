# Custom Ciphersuite

This scenario demonstrates how to create a custom ciphersuite implementation by combining different cryptographic primitives. While ts-mls comes with several built-in ciphersuites, you can create your own by mixing and matching hash functions, HPKE implementations, signature schemes, and KDFs.

## Steps Covered

1. **Import Base Implementation**: Start with a standard ciphersuite as a base.
2. **Define Custom Hash**: Implement a custom hash function (Blake3 in this example).
3. **Create Custom Ciphersuite**: Build a `CiphersuiteImpl` by combining the custom hash with other primitives.

## Key Concepts

- **CiphersuiteImpl**: The interface that defines all cryptographic primitives used by MLS (hash, HPKE, signature, KDF, RNG).
- **Hash**: Interface for hash and MAC operations, including `digest`, `mac`, and `verifyMac` methods.
- **Custom Primitives**: You can implement any of the cryptographic interfaces to use different algorithms.
- **Ciphersuite ID**: Custom ciphersuites should use IDs in the application-specific range to avoid conflicts with standard ciphersuites.

---

```typescript
import {
  createGroup,
  joinGroup,
  createCommit,
  protocolVersions,
  Capabilities,
  Credential,
  defaultCredentialTypes,
  getCiphersuiteImpl,
  generateKeyPackage,
  defaultProposalTypes,
  unsafeTestingAuthenticationService,
  CiphersuiteImpl,
  Hash,
  createApplicationMessage,
  processMessage,
} from "ts-mls"
import { blake3 } from "@noble/hashes/blake3.js"

// Define a custom ciphersuite ID (using application-specific range)
const ciphersuiteId = 0xf000

// Start with a base implementation to reuse some primitives
const defaultImpl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")

// Helper function for constant-time comparison
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a[i]! ^ b[i]!
  }
  return result === 0
}

// Implement Blake3 hash function
const blake3Hash: Hash = {
  async digest(data: Uint8Array) {
    return blake3(data)
  },
  async mac(key: Uint8Array, data: Uint8Array) {
    return blake3(data, { key })
  },
  async verifyMac(key: Uint8Array, mac: Uint8Array, data: Uint8Array) {
    const computedMac = blake3(data, { key })
    return constantTimeEqual(computedMac, mac)
  },
}

// Create custom ciphersuite: "MLS_128_DHKEMX25519_AES128GCM_BLAKE3_Ed25519"
// Uses Blake3 hash instead of SHA-256, while keeping other primitives
const customCiphersuiteImpl: CiphersuiteImpl = {
  hash: blake3Hash, // Custom Blake3 hash
  hpke: defaultImpl.hpke, // Reuse X25519 HPKE
  signature: defaultImpl.signature, // Reuse Ed25519 signatures
  kdf: defaultImpl.kdf, // Reuse standard KDF
  rng: defaultImpl.rng, // Reuse standard RNG
  id: ciphersuiteId,
}

const context = { cipherSuite: customCiphersuiteImpl, authService: unsafeTestingAuthenticationService }

const capabilities: Capabilities = {
  extensions: [],
  credentials: [defaultCredentialTypes.basic],
  proposals: [],
  versions: [protocolVersions.mls10],
  ciphersuites: [ciphersuiteId], // Declare support for custom ciphersuite
}

// Setup Alice's credential with custom capabilities
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({
  credential: aliceCredential,
  capabilities,
  cipherSuite: customCiphersuiteImpl,
})

const groupId = new TextEncoder().encode("group1")

// Alice creates the group with the custom ciphersuite
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})
```

## Notes

- **Ciphersuite Components**: A ciphersuite consists of hash, HPKE, signature, KDF, and RNG implementations.
- **Custom Ciphersuite IDs**: Use IDs in the application-specific range (0xF000-0xFFFF) to avoid conflicts.
- **Algorithm Requirements**: Your custom implementations must fulfill the interface contracts for security and correctness.
- **Blake3**: This example uses Blake3, a modern cryptographic hash function that's faster than SHA-256 while maintaining security.
- **Reusing Primitives**: You can reuse standard implementations (HPKE, signatures, KDF, RNG) while customizing specific components.
- **Testing**: Thoroughly test custom ciphersuites to ensure they meet security requirements and perform correctly.
- **Interoperability**: Custom ciphersuites are only compatible with implementations that support the same algorithms.
- **Use Cases**: Custom ciphersuites are useful for:
  - Experimental or post-quantum algorithms
  - Hardware-accelerated cryptography
  - Specific compliance requirements
  - Performance optimization for particular environments
