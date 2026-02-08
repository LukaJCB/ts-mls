# Custom Crypto Provider

This scenario demonstrates how to create a custom crypto provider to control how ciphersuites are instantiated. While ts-mls provides a default crypto provider, you can create your own to customize cryptographic implementations, integrate with hardware security modules (HSMs), or use alternative libraries.

## Steps Covered

1. **Implement Custom KDF**: Create a custom KDF implementation using an alternative library.
2. **Create Crypto Provider**: Build a `CryptoProvider` that returns modified ciphersuite implementations.
3. **Use Custom Provider**: Pass the custom provider to `getCiphersuiteImpl` to get customized ciphersuites.

## Key Concepts

- **CryptoProvider**: An interface that controls how ciphersuites are instantiated, allowing you to customize cryptographic implementations.
- **getCiphersuiteImpl**: Accepts an optional crypto provider parameter to retrieve customized ciphersuite implementations.
- **Custom Implementations**: You can provide alternative implementations for any cryptographic primitive (KDF, hash, HPKE, signatures, etc.).
- **Provider Pattern**: The provider pattern allows centralized control over cryptographic implementations across your application.
- **Default Provider**: ts-mls includes a `defaultCryptoProvider` that you can extend or replace.

---

```typescript
import {
  createGroup,
  joinGroup,
  createCommit,
  createApplicationMessage,
  processMessage,
  Credential,
  defaultCredentialTypes,
  getCiphersuiteImpl,
  generateKeyPackage,
  defaultProposalTypes,
  unsafeTestingAuthenticationService,
  CryptoProvider,
  defaultCryptoProvider,
  CiphersuiteImpl,
  ciphersuites,
  Kdf,
} from "ts-mls"
import { extract, expand } from "@noble/hashes/hkdf.js"
import { sha256 } from "@noble/hashes/sha2.js"

// Implement a custom KDF using @noble/hashes
const customSha256Hkdf: Kdf = {
  async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
    return extract(sha256, ikm, salt)
  },
  async expand(prk: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> {
    return expand(sha256, prk, info, len)
  },
  size: 32,
}

// Create a custom crypto provider
const customProvider: CryptoProvider = {
  async getCiphersuiteImpl(id: number): Promise<CiphersuiteImpl> {
    // Get the default implementation as a base
    const defaultImpl = await defaultCryptoProvider.getCiphersuiteImpl(id)

    // Customize the implementation for specific ciphersuites
    if (id === ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) {
      // Replace the KDF with our custom implementation
      return { ...defaultImpl, kdf: customSha256Hkdf }
    } else {
      // Use default implementation for other ciphersuites
      return defaultImpl
    }
  },
}

// Get ciphersuite implementation using the custom provider
const impl: CiphersuiteImpl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", customProvider)

const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }

// Setup credentials
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({
  credential: aliceCredential,
  cipherSuite: impl,
})

const groupId = new TextEncoder().encode("group1")

// Alice creates the group using the custom crypto provider
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})
```

## Notes

- **CryptoProvider Interface**: Defines a single method `getCiphersuiteImpl(id: number)` that returns a `CiphersuiteImpl` for the requested ciphersuite ID.
- **Default Provider**: Use `defaultCryptoProvider` as a base and customize specific ciphersuites as needed.
- **Selective Customization**: You can customize some ciphersuites while leaving others with default implementations.
- **Component Replacement**: Replace any cryptographic component (KDF, hash, HPKE, signature, RNG) based on your needs.
- **Consistency Required**: All members of a group must use compatible cryptographic implementations for operations to succeed.
- **Use Cases**: Custom crypto providers are useful for:
  - Integrating with Hardware Security Modules (HSMs)
  - Using alternative cryptographic libraries
  - Implementing platform-specific optimizations
  - Meeting compliance requirements for specific crypto implementations
  - Testing with mock implementations
  - Adding logging or monitoring around crypto operations
- **Provider Scope**: Pass the same provider to `getCiphersuiteImpl` throughout your application for consistent behavior.
- **Alternative Libraries**: This example uses `@noble/hashes` for KDF, but you can use any library that implements the required interfaces.
- **Performance**: Custom providers allow you to optimize cryptographic operations for your specific platform or hardware.
