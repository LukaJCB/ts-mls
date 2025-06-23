# ts-mls: A TypeScript MLS (Messaging Layer Security - RFC 9420) implementation

[![CI](https://github.com/LukaJCB/ts-mls/actions/workflows/ci.yml/badge.svg)](https://github.com/LukaJCB/ts-mls/actions/workflows/ci.yml) [![npm version](https://badge.fury.io/js/ts-mls.svg)](https://badge.fury.io/js/ts-mls)

Typescript implementation of Messaging Layer Security (RFC 9420, MLS).

This project aims to be a full implementation of [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420) and focuses on immutability and type safety. It is suitable for browsers, Node.js, or serverless environments and supports the recently standardized Post Quantum public-key algorithms (FIPS-203, FIPS-204) as well as the X-Wing hybrid KEM combining X25519 and ML-KEM.

## Installation

```bash
# npm
npm install ts-mls

# yarn
yarn add ts-mls

# pnpm
pnpm add ts-mls
```

This project currently only has a single dependency, `@hpke/core`. However, to support different Ciphersuites, you may need to install other libraries. As an example, to use the `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` Ciphersuite, you would also have to install `@noble/curves`:

```bash
# npm
npm install @noble/curves

# yarn
yarn add @noble/curves

# pnpm
pnpm add @noble/curves
```

Please refer to the subsequent table to understand which additional dependencies are required to install for each Ciphersuite.

## Supported Ciphersuites

The following cipher suites are supported:

| KEM                      | AEAD             | KDF         | Hash    | Signature | Name                                                | ID  | Dependencies                                                        |
| ------------------------ | ---------------- | ----------- | ------- | --------- | --------------------------------------------------- | --- | ------------------------------------------------------------------- |
| DHKEM-X25519-HKDF-SHA256 | AES128GCM        | HKDF-SHA256 | SHA-256 | Ed25519   | MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519        | 1   | @noble/curves                                                       |
| DHKEM-P256-HKDF-SHA256   | AES128GCM        | HKDF-SHA256 | SHA-256 | P256      | MLS_128_DHKEMP256_AES128GCM_SHA256_P256             | 2   | @noble/curves                                                       |
| DHKEM-X25519-HKDF-SHA256 | CHACHA20POLY1305 | HKDF-SHA256 | SHA-256 | Ed25519   | MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 | 3   | @hpke/chacha20poly1305, @noble/curves                               |
| DHKEM-X448-HKDF-SHA512   | AES256GCM        | HKDF-SHA512 | SHA-512 | Ed448     | MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448            | 4   | @noble/curves                                                       |
| DHKEM-P521-HKDF-SHA512   | AES256GCM        | HKDF-SHA512 | SHA-512 | P521      | MLS_256_DHKEMP521_AES256GCM_SHA512_P521             | 5   | @noble/curves                                                       |
| DHKEM-X448-HKDF-SHA512   | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | Ed448     | MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448     | 6   | @hpke/chacha20poly1305, @noble/curves                               |
| DHKEM-P384-HKDF-SHA384   | AES256GCM        | HKDF-SHA384 | SHA-384 | P384      | MLS_256_DHKEMP384_AES256GCM_SHA384_P384             | 7   | @noble/curves                                                       |
| ML-KEM-512               | AES256GCM        | HKDF-SHA256 | SHA-256 | Ed25519   | MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519           | 77  | @hpke/ml-kem, @noble/curves                                         |
| ML-KEM-512               | CHACHA20POLY1305 | HKDF-SHA256 | SHA-256 | Ed25519   | MLS_128_MLKEM512_CHACHA20POLY1305_SHA256_Ed25519    | 78  | @hpke/ml-kem, @hpke/chacha20poly1305, @noble/curves                 |
| ML-KEM-768               | AES256GCM        | HKDF-SHA384 | SHA-384 | Ed25519   | MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519           | 79  | @hpke/ml-kem, @noble/curves                                         |
| ML-KEM-768               | CHACHA20POLY1305 | HKDF-SHA384 | SHA-384 | Ed25519   | MLS_256_MLKEM768_CHACHA20POLY1305_SHA384_Ed25519    | 80  | @hpke/ml-kem, @hpke/chacha20poly1305, @noble/curves                 |
| ML-KEM-1024              | AES256GCM        | HKDF-SHA512 | SHA-512 | Ed25519   | MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519          | 81  | @hpke/ml-kem, @noble/curves                                         |
| ML-KEM-1024              | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | Ed25519   | MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_Ed25519   | 82  | @hpke/ml-kem, @hpke/chacha20poly1305, @noble/curves                 |
| X-Wing                   | AES256GCM        | HKDF-SHA512 | SHA-512 | Ed25519   | MLS_256_XWING_AES256GCM_SHA512_Ed25519              | 83  | @hpke/hybridkem-x-wing, @noble/curves                               |
| X-Wing                   | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | Ed25519   | MLS_256_XWING_CHACHA20POLY1305_SHA512_Ed25519       | 84  | @hpke/hybridkem-x-wing, @hpke/chacha20poly1305, @noble/curves       |
| ML-KEM-1024              | AES256GCM        | HKDF-SHA512 | SHA-512 | ML-DSA-87 | MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA78          | 85  | @hpke/ml-kem, @noble/post-quantum                                   |
| ML-KEM-1024              | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | ML-DSA-87 | MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA78   | 86  | @hpke/ml-kem, @hpke/chacha20poly1305, @noble/post-quantum           |
| X-Wing                   | AES256GCM        | HKDF-SHA512 | SHA-512 | ML-DSA-87 | MLS_256_XWING_AES256GCM_SHA512_MLDSA78              | 87  | @hpke/hybridkem-x-wing, @noble/post-quantum                         |
| X-Wing                   | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | ML-DSA-87 | MLS_256_XWING_CHACHA20POLY1305_SHA512_MLDSA78       | 88  | @hpke/hybridkem-x-wing, @hpke/chacha20poly1305, @noble/post-quantum |

## Security Disclaimer

This library has not undergone a formal security audit. While care has been taken to implement the MLS protocol correctly and securely, it may contain undiscovered vulnerabilities. If you plan to use this library in a production or security-critical context, proceed with caution and consider conducting an independent security review.

## Basic Usage

```typescript
import {
  createApplicationMessage,
  createCommit,
  createGroup,
  joinGroup,
  processPrivateMessage,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  Credential,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
  generateKeyPackage,
  encodeMlsMessage,
  decodeMlsMessage,
  ProposalAdd,
} from "ts-mls"

const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))

// alice generates her key package
const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)

const groupId = new TextEncoder().encode("group1")

// alice creates a new group
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

// bob generates her key package
const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

// bob sends keyPackage to alice
const keyPackageMessage = encodeMlsMessage({
  keyPackage: bob.publicPackage,
  wireformat: "mls_key_package",
  version: "mls10",
})

// alice decodes bob's keyPackage
const decodedKeyPackage = decodeMlsMessage(keyPackageMessage, 0)![0]

if (decodedKeyPackage.wireformat !== "mls_key_package") throw new Error("Expected key package")

// alice creates proposal to add bob
const addBobProposal: ProposalAdd = {
  proposalType: "add",
  add: {
    keyPackage: decodedKeyPackage.keyPackage,
  },
}

// alice commits
const commitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)

aliceGroup = commitResult.newState

// alice sends welcome message to bob
const encodedWelcome = encodeMlsMessage({
  welcome: commitResult.welcome!,
  wireformat: "mls_welcome",
  version: "mls10",
})

// bob decodes the welcome message
const decodedWelcome = decodeMlsMessage(encodedWelcome, 0)![0]

if (decodedWelcome.wireformat !== "mls_welcome") throw new Error("Expected welcome")

// bob creates his own group state
let bobGroup = await joinGroup(
  decodedWelcome.welcome,
  bob.publicPackage,
  bob.privatePackage,
  emptyPskIndex,
  impl,
  aliceGroup.ratchetTree,
)

const messageToBob = new TextEncoder().encode("Hello bob!")

// alice creates a message to the group
const aliceCreateMessageResult = await createApplicationMessage(aliceGroup, messageToBob, impl)

aliceGroup = aliceCreateMessageResult.newState

// alice sends the message to bob
const encodedPrivateMessageAlice = encodeMlsMessage({
  privateMessage: aliceCreateMessageResult.privateMessage,
  wireformat: "mls_private_message",
  version: "mls10",
})

// bob decodes the message
const decodedPrivateMessageAlice = decodeMlsMessage(encodedPrivateMessageAlice, 0)![0]

if (decodedPrivateMessageAlice.wireformat !== "mls_private_message") throw new Error("Expected private message")

// bob receives the message
const bobProcessMessageResult = await processPrivateMessage(
  bobGroup,
  decodedPrivateMessageAlice.privateMessage,
  emptyPskIndex,
  impl,
)

bobGroup = bobProcessMessageResult.newState

if (bobProcessMessageResult.kind === "newState") throw new Error("Expected application message")

console.log(bobProcessMessageResult.message)
```

## Documentation

Please visit the [/docs directory](docs/) for further documentation on different scenarios.

## Contributing

We welcome contributions! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to set up your environment, run checks, and submit changes.

# License

[MIT](LICENSE)
