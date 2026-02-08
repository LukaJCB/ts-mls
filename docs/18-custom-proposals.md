# Custom Proposals

This scenario demonstrates how to create and process custom (application-defined) proposal types. While MLS defines standard proposals like Add, Remove, and Update, applications can define their own proposal types to extend MLS functionality for specific use cases.

## Steps Covered

1. **Define Custom Proposal Type**: Choose a proposal type ID in the application-specific range.
2. **Setup Capabilities**: Include the custom proposal type in member capabilities.
3. **Group Creation**: Create a group with members that support the custom proposal.
4. **Create Custom Proposal**: Bob creates a proposal with custom data.
5. **Process Proposal**: Alice receives and inspects the custom proposal using a callback.
6. **Commit Proposal**: Alice commits the custom proposal.
7. **Process Commit**: Bob receives the commit and sees the custom proposal was applied.

## Key Concepts

- **Custom Proposal Types**: Application-defined proposals using IDs in the application-specific range (0xF000 - 0xFFFF).
- **Capabilities**: Members must declare support for custom proposal types in their capabilities before using them.
- **Proposal Data**: Custom proposals can carry arbitrary data relevant to the application.
- **Callback Inspection**: When processing messages, callbacks can inspect custom proposals to implement application-specific validation.

---

```typescript
import {
  createGroup,
  joinGroup,
  createCommit,
  createProposal,
  createApplicationMessage,
  processMessage,
  isDefaultProposal,
  processPrivateMessage,
  Credential,
  defaultCredentialTypes,
  getCiphersuiteImpl,
  generateKeyPackage,
  Proposal,
  Capabilities,
  protocolVersions,
  ciphersuites,
  defaultProposalTypes,
  wireformats,
  unsafeTestingAuthenticationService,
  UsageError,
  zeroOutUint8Array,
} from "ts-mls"

// Setup ciphersuite
const impl = await getCiphersuiteImpl("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }

// Define a custom proposal type (using application-specific range)
const customProposalType: number = 0xf000

// Define capabilities that include the custom proposal type
const capabilities: Capabilities = {
  extensions: [],
  credentials: [defaultCredentialTypes.basic],
  proposals: [customProposalType], // Declare support for custom proposal
  versions: [protocolVersions.mls10],
  ciphersuites: [ciphersuites["MLS_256_XWING_AES256GCM_SHA512_Ed25519"]],
}

// Setup Alice's credential with custom capabilities
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}
const alice = await generateKeyPackage({
  credential: aliceCredential,
  capabilities,
  cipherSuite: impl,
})

const groupId = new TextEncoder().encode("group1")

// Alice creates the group
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})

// Setup Bob's credential with the same capabilities
const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage({
  credential: bobCredential,
  capabilities,
  cipherSuite: impl,
})

// Alice adds Bob to the group
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

// Bob joins the group
let bobGroup = await joinGroup({
  context,
  welcome: addBobCommitResult.welcome!.welcome,
  keyPackage: bob.publicPackage,
  privateKeys: bob.privatePackage,
  ratchetTree: aliceGroup.ratchetTree,
})

// Bob creates a custom proposal with application-specific data
const proposalData = new TextEncoder().encode("custom proposal data")

const customProposal: Proposal = {
  proposalType: customProposalType,
  proposalData: proposalData,
}

const createProposalResult = await createProposal({
  context,
  state: bobGroup,
  wireAsPublicMessage: false,
  proposal: customProposal,
})

bobGroup = createProposalResult.newState
createProposalResult.consumed.forEach(zeroOutUint8Array)

// Alice receives and processes the custom proposal
const processProposalResult = await processMessage({
  context,
  state: aliceGroup,
  message: createProposalResult.message,
  callback: (p) => {
    if (p.kind !== "proposal" || isDefaultProposal(p.proposal.proposal)) throw new Error("Expected custom proposal")

    // Inspect the custom proposal
    if (p.proposal.proposal.proposalData) {
      const data = new TextDecoder().decode(p.proposal.proposal.proposalData)
    }

    // Application can validate the custom proposal here

    return "accept" // Accept the proposal or reject it
  },
})

aliceGroup = processProposalResult.newState
processProposalResult.consumed.forEach(zeroOutUint8Array)

// Alice commits the custom proposal
const createCommitResult = await createCommit({
  context,
  state: aliceGroup,
})

aliceGroup = createCommitResult.newState
createCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob processes the commit
const processCommitResult = await processMessage({
  context,
  state: bobGroup,
  message: createCommitResult.commit,
  callback: (p) => {
    if (p.kind !== "commit") throw new Error("Expected commit")

    // Bob can see the custom proposal in the commit
    const proposals = p.proposals.map((p) => p.proposal)

    if (proposals[0] && !isDefaultProposal(proposals[0]) && proposals[0].proposalData) {
      const data = new TextDecoder().decode(proposals[0].proposalData)
    }

    return "accept"
  },
})

bobGroup = processCommitResult.newState
processCommitResult.consumed.forEach(zeroOutUint8Array)
```

## Notes

- **Proposal Type Range**: Use IDs (0xF000 - 0xFFFF) for custom proposal types to avoid conflicts.
- **Capabilities**: All group members must declare support for custom proposal types in their capabilities before those proposals can be used.
- **Proposal Data**: Custom proposals can include arbitrary binary data (`proposalData`) that's meaningful to your application.
- **Application Semantics**: The MLS protocol doesn't interpret custom proposals—your application defines what they mean and how to validate them.
- **Validation in Callbacks**: Use the callback parameter in `processMessage` to inspect and validate custom proposals before accepting them.
- **Commit Required**: Custom proposals must be committed before they take effect, just like standard proposals.
