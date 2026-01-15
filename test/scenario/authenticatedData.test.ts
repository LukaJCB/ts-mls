import { createGroup, joinGroup, makePskIndex } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { createApplicationMessage, createProposal } from "../../src/createMessage.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { Credential } from "../../src/credential.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { CryptoError, CryptoVerificationError } from "../../src/mlsError.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { processPrivateMessage, processPublicMessage } from "../../src/processMessages.js"
import { Capabilities } from "../../src/capabilities.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal } from "../../src/proposal.js"

test.concurrent.each(Object.keys(ciphersuites))("authenticatedData verified for app/proposal/commit %s", async (cs) => {
  await authenticatedDataScenario(cs as CiphersuiteName)
})

async function authenticatedDataScenario(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))
  const encoder = new TextEncoder()

  const customProposalType = 8

  const base = defaultCapabilities()
  const capabilities: Capabilities = {
    ...base,
    proposals: Array.from(new Set([...base.proposals, customProposalType])),
    credentials: ["basic"],
    versions: ["mls10"],
    ciphersuites: [cipherSuite],
  }

  const aliceCredential: Credential = {
    credentialType: "basic",
    identity: encoder.encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, capabilities, defaultLifetime, [], impl)

  const bobCredential: Credential = {
    credentialType: "basic",
    identity: encoder.encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, capabilities, defaultLifetime, [], impl)

  const groupId = encoder.encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const addBobCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    { extraProposals: [{ proposalType: "add", add: { keyPackage: bob.publicPackage } }] },
  )

  aliceGroup = addBobCommitResult.newState

  let bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  const appAuthenticatedData = encoder.encode("aad-app")
  const appMessage = encoder.encode("hello bob")

  const aliceAppResult = await createApplicationMessage(aliceGroup, appMessage, impl, appAuthenticatedData)
  aliceGroup = aliceAppResult.newState

  const tamperedApp = { ...aliceAppResult.privateMessage, authenticatedData: encoder.encode("aad-app-tampered") }
  await expect(processPrivateMessage(bobGroup, tamperedApp, makePskIndex(bobGroup, {}), impl)).rejects.toThrow(
    CryptoError,
  )

  const bobAppResult = await processPrivateMessage(
    bobGroup,
    aliceAppResult.privateMessage,
    makePskIndex(bobGroup, {}),
    impl,
  )

  if (bobAppResult.kind === "newState") throw new Error("Expected application message")
  expect(bobAppResult.message).toStrictEqual(appMessage)
  bobGroup = bobAppResult.newState

  const proposalAuthenticatedData = encoder.encode("aad-proposal")
  const customProposal: Proposal = {
    proposalType: customProposalType,
    proposalData: encoder.encode("custom proposal data"),
  }

  const bobProposalResult = await createProposal(bobGroup, false, customProposal, impl, proposalAuthenticatedData)
  bobGroup = bobProposalResult.newState

  if (bobProposalResult.message.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const tamperedProposal = {
    ...bobProposalResult.message.privateMessage,
    authenticatedData: encoder.encode("aad-proposal-tampered"),
  }
  await expect(
    processPrivateMessage(aliceGroup, tamperedProposal, makePskIndex(aliceGroup, {}), impl, () => {
      throw new Error("Callback should not run for tampered authenticatedData")
    }),
  ).rejects.toThrow(CryptoError)

  const aliceProcessProposalResult = await processPrivateMessage(
    aliceGroup,
    bobProposalResult.message.privateMessage,
    makePskIndex(aliceGroup, {}),
    impl,
    (incoming) => {
      if (incoming.kind !== "proposal") throw new Error("Expected proposal")
      expect(incoming.proposal.proposal).toStrictEqual(customProposal)
      return "accept"
    },
  )

  if (aliceProcessProposalResult.kind !== "newState") throw new Error("Expected new state")
  aliceGroup = aliceProcessProposalResult.newState

  const commitAuthenticatedData = encoder.encode("aad-commit")

  const aliceCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    { authenticatedData: commitAuthenticatedData },
  )

  aliceGroup = aliceCommitResult.newState

  if (aliceCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const tamperedCommit = {
    ...aliceCommitResult.commit.privateMessage,
    authenticatedData: encoder.encode("aad-commit-tampered"),
  }
  await expect(
    processPrivateMessage(bobGroup, tamperedCommit, makePskIndex(bobGroup, {}), impl, () => {
      throw new Error("Callback should not run for tampered authenticatedData")
    }),
  ).rejects.toThrow(CryptoError)

  const bobProcessCommitResult = await processPrivateMessage(
    bobGroup,
    aliceCommitResult.commit.privateMessage,
    makePskIndex(bobGroup, {}),
    impl,
    (incoming) => {
      if (incoming.kind !== "commit") throw new Error("Expected commit")
      expect(incoming.proposals.map((p) => p.proposal)).toStrictEqual([customProposal])
      return "accept"
    },
  )

  if (bobProcessCommitResult.kind !== "newState") throw new Error("Expected new state")
  bobGroup = bobProcessCommitResult.newState

  const publicProposalAuthenticatedData = encoder.encode("aad-proposal-public")
  const customProposalPublic: Proposal = {
    proposalType: customProposalType,
    proposalData: encoder.encode("custom proposal data (public)"),
  }

  const bobProposalPublicResult = await createProposal(
    bobGroup,
    true,
    customProposalPublic,
    impl,
    publicProposalAuthenticatedData,
  )

  bobGroup = bobProposalPublicResult.newState

  if (bobProposalPublicResult.message.wireformat !== "mls_public_message") throw new Error("Expected public message")

  const tamperedPublicProposal = {
    ...bobProposalPublicResult.message.publicMessage,
    content: {
      ...bobProposalPublicResult.message.publicMessage.content,
      authenticatedData: encoder.encode("aad-proposal-public-tampered"),
    },
  }

  await expect(
    processPublicMessage(aliceGroup, tamperedPublicProposal, makePskIndex(aliceGroup, {}), impl),
  ).rejects.toThrow(CryptoVerificationError)

  const aliceProcessPublicProposalResult = await processPublicMessage(
    aliceGroup,
    bobProposalPublicResult.message.publicMessage,
    makePskIndex(aliceGroup, {}),
    impl,
    (incoming) => {
      if (incoming.kind !== "proposal") throw new Error("Expected proposal")
      expect(incoming.proposal.proposal).toStrictEqual(customProposalPublic)
      return "accept"
    },
  )

  aliceGroup = aliceProcessPublicProposalResult.newState

  const publicCommitAuthenticatedData = encoder.encode("aad-commit-public")

  const alicePublicCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    {
      wireAsPublicMessage: true,
      authenticatedData: publicCommitAuthenticatedData,
    },
  )

  aliceGroup = alicePublicCommitResult.newState

  if (alicePublicCommitResult.commit.wireformat !== "mls_public_message") throw new Error("Expected public message")

  const tamperedPublicCommit = {
    ...alicePublicCommitResult.commit.publicMessage,
    content: {
      ...alicePublicCommitResult.commit.publicMessage.content,
      authenticatedData: encoder.encode("aad-commit-public-tampered"),
    },
  }

  await expect(processPublicMessage(bobGroup, tamperedPublicCommit, makePskIndex(bobGroup, {}), impl)).rejects.toThrow(
    CryptoVerificationError,
  )

  const bobProcessPublicCommitResult = await processPublicMessage(
    bobGroup,
    alicePublicCommitResult.commit.publicMessage,
    makePskIndex(bobGroup, {}),
    impl,
    (incoming) => {
      if (incoming.kind !== "commit") throw new Error("Expected commit")
      expect(incoming.proposals.map((p) => p.proposal)).toStrictEqual([customProposalPublic])
      return "accept"
    },
  )

  bobGroup = bobProcessPublicCommitResult.newState

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
}
