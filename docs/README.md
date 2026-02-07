# ts-mls Documentation Index

This directory contains comprehensive scenario-based documentation for ts-mls, a TypeScript implementation of the Messaging Layer Security (MLS) protocol. Each document provides working code examples and detailed explanations of specific features and use cases.

## Getting Started

Start here to learn the basics of using ts-mls:

- **[01-basic-functionality.md](01-basic-functionality.md)** - The most fundamental MLS workflow: creating a group, adding a member, and exchanging encrypted messages.

## Core Operations

Learn about essential group operations:

- **[02-ratchet-tree-extension.md](02-ratchet-tree-extension.md)** - Using the Ratchet Tree Extension to include group state in Welcome messages, simplifying member onboarding.
- **[03-three-party-join.md](03-three-party-join.md)** - Adding multiple members sequentially and ensuring all members can communicate securely.
- **[04-remove.md](04-remove.md)** - Removing members from a group and updating the remaining members' state.
- **[05-update.md](05-update.md)** - Updating member keys with empty commits to refresh cryptographic material.
- **[06-multiple-joins-at-once.md](06-multiple-joins-at-once.md)** - Efficiently adding multiple members in a single commit operation.

## Advanced Group Management

Explore advanced membership and group lifecycle features:

- **[07-external-join.md](07-external-join.md)** - Joining a group externally using GroupInfo objects, useful for open groups.
- **[09-resumption.md](09-resumption.md)** - Branching a group with a subset of participants, creating a new linked group.
- **[10-reinit.md](10-reinit.md)** - Reinitializing a group with new parameters (group ID, ciphersuite) while maintaining membership.
- **[11-reject-incoming-message.md](11-reject-incoming-message.md)** - Implementing fine-grained control by rejecting incoming proposals and commits.

## Security Features

Learn about advanced security mechanisms:

- **[08-external-psk.md](08-external-psk.md)** - Injecting external pre-shared keys (PSKs) into the group key schedule for additional security.
- **[19-authenticated-data.md](19-authenticated-data.md)** - Using Additional Authenticated Data (AAD) to attach tamper-proof metadata to messages.

## Extensions and Customization

Extend MLS with application-specific functionality:

- **[12-custom-extensions.md](12-custom-extensions.md)** - Adding custom extensions to the group context with capability validation.
- **[13-groupinfo-custom-extensions.md](13-groupinfo-custom-extensions.md)** - Creating groups with custom extensions visible to all members through GroupInfo.
- **[18-custom-proposals.md](18-custom-proposals.md)** - Defining and processing application-specific proposal types.

## State Management and Inspection

Tools for managing and inspecting group state:

- **[14-group-state-inspection.md](14-group-state-inspection.md)** - Retrieving member information, accessing leaf nodes, and reusing signature keys across groups.
- **[15-client-state-serialization.md](15-client-state-serialization.md)** - Serializing and deserializing client state for persistence and session resumption.

## Cryptographic Customization

Advanced cryptographic configuration:

- **[16-custom-ciphersuite.md](16-custom-ciphersuite.md)** - Creating custom ciphersuites by combining different cryptographic primitives (hash, HPKE, signatures, KDF).
- **[17-custom-crypto-provider.md](17-custom-crypto-provider.md)** - Implementing custom crypto providers for HSM integration, alternative libraries, or platform-specific optimizations.

## Migration

- **[migration-guide.md](migration-guide.md)** - Guide for migrating between versions 1.x and 2.x of ts-mls.

## Documentation Organization

The documentation is organized numerically (01-19) to provide a progressive learning path, starting with basic concepts and moving to advanced features. However, you can read any document independently based on your specific needs.

## Running the Examples

All code examples in this documentation are executable. They use:

- The `ts-mls` library with standard imports
- A test authentication service (`unsafeTestingAuthenticationService`) for demonstration purposes
- Common cryptographic operations and message patterns

To use these examples in your application:

1. Install ts-mls: `npm install ts-mls` or `pnpm add ts-mls`
2. Replace `unsafeTestingAuthenticationService` with your own authentication implementation
3. Adapt the examples to your specific use case

## Additional Resources

- **Test Suite**: The `test/scenario/` directory contains the test implementations that correspond to these documentation files
- **RFC 9420**: The official [MLS protocol specification](https://www.rfc-editor.org/rfc/rfc9420.html)

## Contributing

Found an issue or want to improve the documentation? Contributions are welcome! Please refer to the main repository's contributing guidelines.
