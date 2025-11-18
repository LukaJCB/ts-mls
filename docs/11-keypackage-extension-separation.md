# KeyPackage Extension Separation

The `generateKeyPackage` function supports an optional `leafNodeExtensions` parameter to properly separate KeyPackage extensions from LeafNode extensions according to MLS specification compliance:

## Key Concepts

- **KeyPackage Extensions**: Extensions that apply to the KeyPackage itself (e.g., `last_resort` extension)
- **LeafNode Extensions**: Extensions that apply specifically to the LeafNode operations
- **Extension Separation**: Proper separation of extension types to ensure MLS specification compliance

## API

```typescript
import {
  Credential,
  Capabilities,
  Lifetime,
  Extension,
  CiphersuiteImpl,
  KeyPackage,
  PrivateKeyPackage,
  generateKeyPackage,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
} from "ts-mls"

// Example usage showing the function signature with proper parameter usage
async function exampleKeyPackageGeneration(): Promise<void> {
  const credential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("user") }
  const capabilities: Capabilities = {
    versions: ["mls10"],
    ciphersuites: ["MLS_256_XWING_AES256GCM_SHA512_Ed25519"],
    extensions: [],
    proposals: [],
    credentials: ["basic"],
  }
  const lifetime: Lifetime = { notBefore: 0n, notAfter: 1000000000n }
  const extensions: Extension[] = [] // KeyPackage extensions
  const cs: CiphersuiteImpl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))
  const leafNodeExtensions: Extension[] = [] // Optional LeafNode extensions

  // Call the actual function
  const result = await generateKeyPackage(credential, capabilities, lifetime, extensions, cs, leafNodeExtensions)

  // Use the result
  const { publicPackage, privatePackage } = result
  console.log("Generated KeyPackage:", publicPackage)
  console.log("Generated PrivateKeyPackage:", privatePackage)
}
```

This ensures compliance with RFC 9420.

## Related test

- [keyPackageExtensionSeparation.test.ts](https://github.com/LukaJCB/ts-mls/blob/main/test/keyPackageExtensionSeparation.test.ts)
