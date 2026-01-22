# Migration guide (from version 1.6.1 -> 2.0.0)

## High-level summary

The major breaking change is that most MLS entrypoints now take a **single params object** with a nested `context` field.

Secondarily, a number of “string-literal enums” were replaced by numeric/value-based types derived from exported constant objects (e.g. `wireformats`, `leafNodeSources`, `senderTypes`, `protocolVersions`, `pskTypes`, etc.), and several extension-related types were split into more specific unions.

## 1) `MlsContext` + `ClientState` replace long positional parameter lists (breaking)

### What changed

The following functions now take a **single params object** whose `context` is `MlsContext` (rather than separate positional args or a `(context, params)` pair):

- `joinGroup(...)`
- `joinGroupWithExtensions(...)`
- `joinGroupExternal(...)`
- `joinGroupFromBranch(...)`
- `joinGroupFromReinit(...)`

The following functions now take a **single params object** with **separate** `context: MlsContext` and `state: ClientState` fields:

- `createCommit(...)`
- `createProposal(...)`
- `createApplicationMessage(...)`
- `processPrivateMessage(...)`
- `processPublicMessage(...)`
- `processMessage(...)`

Additionally, several helpers now take `context: MlsContext` explicitly (rather than getting `authService` via
`ClientConfig`):

- `createGroup(...)`
- `branchGroup(...)`
- `reinitGroup(...)`
- `reinitCreateNewGroup(...)`

`createCommit(...)` now returns `welcome` as a wrapped `MlsWelcomeMessage`. When calling `joinGroup*`, pass the inner `welcome` payload (e.g. `commitResult.welcome!.welcome`).

Key package generation now uses a params object as well:

- `generateKeyPackage(...)`
- `generateKeyPackageWithKey(...)`

`capabilities`, `lifetime`, and `extensions` are optional in these helpers; if omitted they default to
`defaultCapabilities()`, `defaultLifetime()`, and `[]`.

### `defaultLifetime` is now a function (breaking for value imports)

In v1, `defaultLifetime` was a constant `Lifetime` value. In v2, it is a function that returns a fresh
`Lifetime` value. If your code referenced the value directly, call it instead (though if you are using the defaultLifetime you can just omit it when calling the above `generateKeyPackage` functions).

Before:

```text
const lifetime = defaultLifetime
await generateKeyPackage(credential, capabilities, lifetime, extensions, cipherSuite)
```

After:

```text
const lifetime = defaultLifetime()
await generateKeyPackage({ credential, capabilities, lifetime, extensions, cipherSuite })
```

As part of that, `ClientConfig` no longer carries `authService`; it is now passed explicitly to the operations that need it.

### Why

Credential validation (and similar authentication decisions) is now an explicit dependency rather than an implicit global/default.

### How to migrate

If you’re writing tests, the library now exposes:

- `unsafeTestingAuthenticationService: AuthenticationService`

You can use this for examples and tests. For production code, implement your own `AuthenticationService`.

#### Before → After examples

**`createGroup`**

Before:

```text
const state = await createGroup(groupId, keyPackage, privateKeyPackage, extensions, authService, cipherSuite)
```

After:

```text
const state = await createGroup({
  context: { cipherSuite, authService },
  groupId,
  keyPackage,
  privateKeyPackage,
  extensions,
})
```

**`joinGroup`**

Before:

```text
const state = await joinGroup(welcome, keyPackage, privateKeys, pskIndex, cipherSuite, ratchetTree)
```

After:

````text
const state = await joinGroup(
  { context: { cipherSuite, authService, externalPsks }, welcome, keyPackage, privateKeys, ratchetTree },
)

If your welcome comes from a commit result:

```text
const state = await joinGroup(
  { context: { cipherSuite, authService, externalPsks }, welcome: commitResult.welcome!.welcome, keyPackage, privateKeys, ratchetTree },
)
````

````

**`joinGroupWithExtensions` (return type change)**

Before:

```text
const [state, groupInfoExtensions] = await joinGroupWithExtensions(
  welcome,
  keyPackage,
  privateKeys,
  pskIndex,
  cipherSuite,
  ratchetTree,
)
````

After:

```text
const { state, groupInfoExtensions } = await joinGroupWithExtensions(
  { context: { cipherSuite, authService, externalPsks }, welcome, keyPackage, privateKeys, ratchetTree },
)
```

**`joinGroupExternal`**

Before:

```text
const { publicMessage, newState } = await joinGroupExternal(groupInfo, keyPackage, privateKeys, resync, cipherSuite)
```

After:

```text
const { publicMessage, newState } = await joinGroupExternal(
  { context: { cipherSuite, authService }, groupInfo, keyPackage, privateKeys, resync },
)
```

**`processPrivateMessage` / `processPublicMessage` / `processMessage`**

Before:

```text
await processPrivateMessage(state, privateMessage, pskIndex, cipherSuite)
await processPublicMessage(state, publicMessage, pskIndex, cipherSuite)
await processMessage(message, state, pskIndex, acceptAll, cipherSuite)
```

After:

```text
await processPrivateMessage(
  { context: { cipherSuite, authService, externalPsks }, state, privateMessage },
)
await processPublicMessage(
  { context: { cipherSuite, authService, externalPsks }, state, publicMessage },
)
await processMessage(
  { context: { cipherSuite, authService, externalPsks }, state, message, callback: acceptAll },
)
```

**`createApplicationMessage` / `createProposal`**

Before:

```text
const { newState, privateMessage } = await createApplicationMessage(state, bytes, cipherSuite, authenticatedData)
const { newState, message } = await createProposal(state, false, proposal, cipherSuite, authenticatedData)
```

After:

```text
const { newState, message } = await createApplicationMessage(
  { context: { cipherSuite, authService, externalPsks }, state, message: bytes, authenticatedData },
)

const { newState, message } = await createProposal(
  { context: { cipherSuite, authService, externalPsks }, state, proposal, wireAsPublicMessage: false, authenticatedData },
)
```

**`createCommit()`**

Before:

```text
const res = await createCommit({ state, cipherSuite, authService }, options)
```

After:

```text
const res = await createCommit({ context: { cipherSuite, authService }, state, ...options })
```

**`branchGroup` / `joinGroupFromBranch`**

Before:

```text
await branchGroup(state, keyPackage, privateKeyPackage, members, newGroupId, cipherSuite)
await joinGroupFromBranch(oldState, welcome, keyPackage, privateKeyPackage, ratchetTree, cipherSuite)
```

After:

```text
await branchGroup({
  context: { cipherSuite, authService },
  state,
  keyPackage,
  privateKeyPackage,
  memberKeyPackages: members,
  newGroupId,
})
await joinGroupFromBranch(
  { context: { cipherSuite, authService }, oldState, welcome, keyPackage, privateKeyPackage, ratchetTree },
)
```

**`reinitGroup` / `reinitCreateNewGroup` / `joinGroupFromReinit`**

Before:

```text
await reinitGroup(state, groupId, versionName, ciphersuiteName, extensions, cipherSuite)
await reinitCreateNewGroup(state, keyPackage, privateKeyPackage, members, groupId, ciphersuiteName, extensions, provider?)
await joinGroupFromReinit(suspended, welcome, keyPackage, privateKeyPackage, ratchetTree, provider?)
```

After:

```text
await reinitGroup({
  context: { cipherSuite, authService },
  state,
  groupId,
  version: versionName,
  cipherSuite: ciphersuiteName,
  extensions,
})
await reinitCreateNewGroup({
  context: { cipherSuite, authService },
  state,
  keyPackage,
  privateKeyPackage,
  memberKeyPackages: members,
  groupId,
  cipherSuite: ciphersuiteName,
  extensions,
  provider,
})
await joinGroupFromReinit(
  {
    context: { cipherSuite, authService },
    suspendedState: suspended,
    welcome,
    keyPackage,
    privateKeyPackage,
    ratchetTree,
    provider,
  },
)
```

## 2) “Name” types replaced by “Value/Id” types (potentially breaking for type-heavy code)

A number of types that used to be string unions (or “name”-based keys) are now “value”-based types derived from exported constant objects.

Notable examples:

- `CiphersuiteName` → many fields now use `CiphersuiteId`
  - `CiphersuiteImpl.name` is now `CiphersuiteId`
  - `GroupContext.cipherSuite`, `Welcome.cipherSuite`, `Reinit.cipherSuite` now use `CiphersuiteId`
- `ProtocolVersionName` → some fields now use `ProtocolVersionValue`
- `ContentTypeName` → `ContentTypeValue`
- `SenderTypeName` → `SenderTypeValue`
- `ResumptionPSKUsageName` → `ResumptionPSKUsageValue`
- `Wireformat` string literals → `WireformatValue` via `wireformats`

### How to migrate

- If you were storing these values as strings (e.g. `"mls_private_message"`), switch to the exported constants (e.g. `wireformats.mls_private_message`).
- If you were using the “name” types heavily, expect some refactors where values are now numbers.

## 3) Extensions are now more strongly typed (potentially breaking)

### What changed

The generic `Extension` type is no longer the primary public shape in many APIs. It’s been split into:

- `CustomExtension`
- `GroupContextExtension` (union)
- `GroupInfoExtension` (union)
- `LeafNodeExtension` (union)

Examples of signature changes:

- `createGroup({ ..., extensions?: GroupContextExtension[] })`
- `createGroupInfoWithExternalPub*(..., extensions: GroupInfoExtension[], ...)`
- `generateKeyPackage(..., extensions: CustomExtension[], ..., leafNodeExtensions?: LeafNodeExtension[])`

### How to migrate

- If you weren’t using extensions: pass `[]` as before (but update the parameter type as needed).
- If you were constructing custom extensions:
  - Use `makeCustomExtension({ extensionType, extensionData })` instead of a plain object.
  - Avoid using reserved/default extension types as `extensionType`.
- If you were using the `required_capabilities` or `external_senders` extensions, set `extensionData` to the object directly (no encoder/decoder is needed).

Example:

```text
import { makeCustomExtension } from "ts-mls"

const ext = makeCustomExtension({ extensionType: 0xff00, extensionData: new Uint8Array([1, 2, 3]) })
```

## 4) Encoding/decoding API reshuffle (breaking)

### What changed

In v1, the library exported specific encoder/decoder constants like `encodeMlsMessage` / `decodeMlsMessage` (and similar).

In v2, these were renamed to more consistent `*Encoder` / `*Decoder` names, and the library now also exposes generic helpers:

- `encode<T>(enc: Encoder<T>, t: T): Uint8Array`
- `decode<T>(dec: Decoder<T>, bytes: Uint8Array): T | undefined`

And exported codecs such as:

- `mlsMessageEncoder` / `mlsMessageDecoder`
- `groupStateEncoder` / `groupStateDecoder`
- `clientStateEncoder` / `clientStateDecoder`

### How to migrate

Before:

```text
const bytes = encodeMlsMessage(msg)
const msg2 = decodeMlsMessage(bytes)
```

After:

```text
const bytes = encode(mlsMessageEncoder, msg)
const msg2 = decode(mlsMessageDecoder, bytes)
```

## 5) Proposal and credential typing changes (type-level breaking)

Notable changes:

- `Proposal` is now `DefaultProposal | ProposalCustom` (instead of a flat union of all default proposal shapes)
- Many `proposalType` fields moved from string literals (e.g. `"add"`) to numeric values (e.g. `typeof defaultProposalTypes.add`)
- Credential typing is more tied to `defaultCredentialTypes` values (e.g. `credentialType: typeof defaultCredentialTypes.basic`) rather than string literals

### How to migrate

- Replace string-literal values with the exported constants (e.g. `defaultProposalTypes.add`, `defaultCredentialTypes.basic`).

## 6) Find/replace cookbook (names + common literals)

These are intentionally “mechanical” edits you can apply with search/replace. For call signature changes (positional → `{ ... }` options objects), you’ll usually still need to touch the surrounding code manually.

### VS Code

- Use **Find in Files**: `Cmd+Shift+F`
- Use **Replace in Files**: `Cmd+Shift+H`
- Toggle regex: the `.*` button in the Find widget

### Common symbol renames (safe global replaces)

- `MLSContext` → `MlsContext`
- `MLSMessage` → `MlsMessage`
- `PreSharedKeyID` → `PskId`
- `PSKInfo` → `PskInfo`
- `PSKInfoExternal` → `PskInfoExternal`
- `PSKInfoResumption` → `PskInfoResumption`
- `PSKNonce` → `PskNonce`
- `welcome: <expr>.welcome!` → `welcome: <expr>.welcome!.welcome`
- `defaultAuthenticationService` → `unsafeTestingAuthenticationService`
- `credentialTypes.` → `defaultCredentialTypes.`
- `encodeMlsMessage(` → `encode(mlsMessageEncoder, `
- `decodeMlsMessage(` → `decode(mlsMessageDecoder, `
- `encodeGroupState(` → `encode(groupStateEncoder, `
- `decodeGroupState(` → `decode(groupStateDecoder, `

### Common literal → constant replaces (usually safe with regex)

- Proposal types:
  - Find (regex): `proposalType:\s*"add"` → Replace: `proposalType: defaultProposalTypes.add`
  - Find (regex): `proposalType:\s*"update"` → Replace: `proposalType: defaultProposalTypes.update`
  - Find (regex): `proposalType:\s*"remove"` → Replace: `proposalType: defaultProposalTypes.remove`
  - Find (regex): `proposalType:\s*"psk"` → Replace: `proposalType: defaultProposalTypes.psk`
  - Find (regex): `proposalType:\s*"reinit"` → Replace: `proposalType: defaultProposalTypes.reinit`
  - Find (regex): `proposalType:\s*"external_init"` → Replace: `proposalType: defaultProposalTypes.external_init`
  - Find (regex): `proposalType:\s*"group_context_extensions"` → Replace: `proposalType: defaultProposalTypes.group_context_extensions`

- Credential types:
  - Find (regex): `credentialType:\s*"basic"` → Replace: `credentialType: defaultCredentialTypes.basic`
  - Find (regex): `credentialType:\s*"x509"` → Replace: `credentialType: defaultCredentialTypes.x509`

- Wireformat string literals (only if you still have them in your code):
  - Find: `"mls_private_message"` → Replace: `wireformats.mls_private_message`
  - Find: `"mls_public_message"` → Replace: `wireformats.mls_public_message`
  - Find: `"mls_welcome"` → Replace: `wireformats.mls_welcome`
  - Find: `"mls_group_info"` → Replace: `wireformats.mls_group_info`
  - Find: `"mls_key_package"` → Replace: `wireformats.mls_key_package`

## Appendix: Quick checklist

- [ ] Pass `authService` to `createGroup`, `branchGroup`, `reinitGroup`, `reinitCreateNewGroup`
- [ ] Switch `joinGroup*` calls to a single params object
- [ ] Switch `createCommit` / `create*Message` / `process*Message` calls to a single params object
- [ ] Switch `branchGroup` / `reinit*` calls to a single params object
- [ ] Switch `generateKeyPackage*` calls to a single params object
- [ ] Add `authService` to every `context` you pass as `MlsContext`
- [ ] Replace string literals (wireformats, sender types, leaf node sources, etc.) with exported constants
- [ ] Update extension arrays to the new `*Extension` union types (or pass `[]`)
- [ ] Update encoding/decoding to `encode(...)` / `decode(...)` + exported codecs
