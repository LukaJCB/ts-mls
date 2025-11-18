# KeyPackage Extension Separation

The `generateKeyPackage` function supports an optional `leafNodeExtensions` parameter to properly separate KeyPackage extensions from LeafNode extensions according to MLS specification compliance:

## Key Concepts

- **KeyPackage Extensions**: Extensions that apply to the KeyPackage itself (e.g., `last_resort` extension)
- **LeafNode Extensions**: Extensions that apply specifically to the LeafNode operations
- **Extension Separation**: Proper separation of extension types to ensure MLS specification compliance

## API

```typescript
async function generateKeyPackage(
  credential: Credential,
  capabilities: Capabilities,
  lifetime: Lifetime,
  extensions: Extension[], // KeyPackage extensions
  cs: CiphersuiteImpl,
  leafNodeExtensions?: Extension[], // Optional LeafNode extensions
): Promise<{ publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }>
```

This ensures compliance with RFC 9420.

## Related test

- [keyPackageExtensionSeparation.test.ts](https://github.com/LukaJCB/ts-mls/blob/main/test/keyPackageExtensionSeparation.test.ts)
