# Reject Incoming Message

This scenario demonstrates how a member can reject incoming messages (both proposals and commits). This is useful for implementing fine-grained control over which group changes are accepted.

## Steps Covered

1. **Group Creation**: Alice creates a new MLS group.
2. **Adding Bob**: Alice adds Bob to the group with an Add proposal and Commit.
3. **Bob Joins**: Bob joins the group using the Welcome message.
4. **Bob Proposes Extensions**: Bob creates a proposal to modify the group context extensions.
5. **Alice Rejects Proposal**: Alice receives Bob's proposal but rejects it, leaving her unapplied proposals empty.
6. **Alice Commits**: Alice creates a commit without including Bob's rejected proposal.
7. **Bob Rejects Commit**: Bob receives Alice's commit but rejects it, and his state remains unchanged.

## Key Concepts

- **Message Rejection**: When processing a message, a callback can return `"reject"` instead of `"accept"` to reject the message.
- **State Preservation**: When a message is rejected, the member's state (epoch, unapplied proposals) remains unchanged.
- **Proposal Rejection**: Rejecting a proposal means it won't be added to the unapplied proposals list.
- **Commit Rejection**: Rejecting a commit means the group state doesn't advance to the next epoch.
- **processMessage**: The function that processes incoming messages and accepts a callback to decide whether to accept or reject the message. Returns a result that includes an `actionTaken` field indicating whether the message was accepted or rejected.
- **actionTaken**: A field in the return value of `processMessage` that indicates the action taken (`"accept"` or `"reject"`), allowing the caller to know the outcome of processing the message.

---

```typescript
import {
  createGroup,
  joinGroup,
  createCommit,
  Credential,
  defaultCredentialTypes,
  getCiphersuiteImpl,
  generateKeyPackage,
  Proposal,
  defaultProposalTypes,
  defaultExtensionTypes,
  createProposal,
  processMessage,
  unsafeTestingAuthenticationService,
  wireformats,
  zeroOutUint8Array,
} from "ts-mls"

// Setup ciphersuite
const impl = await getCiphersuiteImpl("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
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

// Alice creates the group
let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})

// Setup Bob's credential
const bobCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("bob"),
}
const bob = await generateKeyPackage({
  credential: bobCredential,
  cipherSuite: impl,
})

// Alice adds Bob to the group
const addBobCommitResult = await createCommit({
  context,
  state: aliceGroup,
  wireAsPublicMessage: true,
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

// Bob proposes to modify group context extensions
const bobProposeExtensions: Proposal = {
  proposalType: defaultProposalTypes.group_context_extensions,
  groupContextExtensions: {
    extensions: [
      {
        extensionType: defaultExtensionTypes.external_senders,
        extensionData: {
          credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array() },
          signaturePublicKey: new Uint8Array(),
        },
      },
    ],
  },
}

const createExtensionsProposalResults = await createProposal({
  context,
  state: bobGroup,
  wireAsPublicMessage: true,
  proposal: bobProposeExtensions,
})

bobGroup = createExtensionsProposalResults.newState
createExtensionsProposalResults.consumed.forEach(zeroOutUint8Array)

// Alice rejects Bob's proposal
const aliceRejectsProposalResult = await processMessage({
  context,
  state: aliceGroup,
  message: createExtensionsProposalResults.message,
  callback: (incoming) => {
    if (incoming.kind === "proposal") {
      // Inspect the proposal
      console.log("Received proposal:", incoming.proposal)
      return "reject"
    }
    throw new Error("Should not happen for a proposal message")
  },
})

aliceGroup = aliceRejectsProposalResult.newState
aliceRejectsProposalResult.consumed.forEach(zeroOutUint8Array)

// Alice commits without including Bob's proposal
const aliceCommitResult = await createCommit({
  context,
  state: aliceGroup,
  wireAsPublicMessage: true,
})

aliceGroup = aliceCommitResult.newState
aliceCommitResult.consumed.forEach(zeroOutUint8Array)

// Bob rejects Alice's commit
const bobRejectsAliceCommitResult = await processMessage({
  context,
  state: bobGroup,
  message: aliceCommitResult.commit,
  callback: (incoming) => {
    if (incoming.kind === "commit") {
      // Inspect the proposals and senderLeafIndex
      console.log("Commit proposals:", incoming.proposals)
      console.log("Commit senderLeafIndex:", incoming.senderLeafIndex)
      return "reject"
    }
    throw new Error("Should not happen for a commit message")
  },
})
bobRejectsAliceCommitResult.consumed.forEach(zeroOutUint8Array)
```

## Notes

- The `callback` parameter in `processMessage` allows you to control whether to accept or reject each incoming message.
- The return value of `processMessage` includes an `actionTaken` field that indicates whether the message was `"accept"` or `"reject"`, allowing you to verify the outcome.
- Message rejection can be used to implement custom validation logic or access control policies.
- When a message is rejected, no state changes occur, making it safe to reject messages that don't meet your requirements.
