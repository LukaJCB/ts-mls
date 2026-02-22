import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { createApplicationMessage, createProposal } from "../../src/createMessage.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CryptoError, CryptoVerificationError } from "../../src/mlsError.js"
import { processPublicMessage } from "../../src/processMessages.js"
import { Capabilities } from "../../src/capabilities.js"

import { protocolVersions } from "../../src/protocolVersion.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal } from "../../src/proposal.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  processPrivateMessageEnsureNoMutation,
} from "./common.js"

test.concurrent.each(Object.keys(ciphersuites))("authenticatedData verified for app/proposal/commit %s", async (cs) => {
  await authenticatedDataScenario(cs as CiphersuiteName)
})

async function authenticatedDataScenario(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)
  const encoder = new TextEncoder()

  const customProposalType = 8

  const base = defaultCapabilities()
  const capabilities: Capabilities = {
    ...base,
    proposals: Array.from(new Set([...base.proposals, customProposalType])),
    credentials: [defaultCredentialTypes.basic],
    versions: [protocolVersions.mls10],
    ciphersuites: [ciphersuites[cipherSuite]],
  }

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: encoder.encode("alice"),
  }
  const alice = await generateKeyPackage({
    credential: aliceCredential,
    capabilities,
    cipherSuite: impl,
  })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: encoder.encode("bob"),
  }
  const bob = await generateKeyPackage({
    credential: bobCredential,
    capabilities,
    cipherSuite: impl,
  })

  const groupId = encoder.encode("group1")

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const addBobCommitResult = await createCommitEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [{ proposalType: 1, add: { keyPackage: bob.publicPackage } }],
  })

  aliceGroup = addBobCommitResult.newState

  let bobGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: addBobCommitResult.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  const appAuthenticatedData = encoder.encode("aad-app")
  const appMessage = encoder.encode("hello bob")

  const aliceAppResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    message: appMessage,
    authenticatedData: appAuthenticatedData,
  })
  aliceGroup = aliceAppResult.newState

  if (aliceAppResult.message.wireformat !== wireformats.mls_private_message) throw new Error("Expected private message")

  const tamperedApp = {
    ...aliceAppResult.message.privateMessage,
    authenticatedData: encoder.encode("aad-app-tampered"),
  }
  await expect(
    processPrivateMessageEnsureNoMutation({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: bobGroup,
      privateMessage: tamperedApp,
    }),
  ).rejects.toThrow(CryptoError)

  const bobAppResult = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    message: aliceAppResult.message,
  })

  if (bobAppResult.kind === "newState") throw new Error("Expected application message")
  expect(bobAppResult.message).toStrictEqual(appMessage)
  expect(bobAppResult.aad).toStrictEqual(appAuthenticatedData)
  bobGroup = bobAppResult.newState

  const proposalAuthenticatedData = encoder.encode("aad-proposal")
  const customProposal: Proposal = {
    proposalType: customProposalType,
    proposalData: encoder.encode("custom proposal data"),
  }

  const bobProposalResult = await createProposal({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    wireAsPublicMessage: false,
    proposal: customProposal,
    authenticatedData: proposalAuthenticatedData,
  })
  bobGroup = bobProposalResult.newState

  if (bobProposalResult.message.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const tamperedProposal = {
    ...bobProposalResult.message.privateMessage,
    authenticatedData: encoder.encode("aad-proposal-tampered"),
  }
  await expect(
    processPrivateMessageEnsureNoMutation({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: aliceGroup,
      privateMessage: tamperedProposal,
      callback: () => {
        throw new Error("Callback should not run for tampered authenticatedData")
      },
    }),
  ).rejects.toThrow(CryptoError)

  const aliceProcessProposalResult = await processMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    message: bobProposalResult.message,
    callback: (incoming) => {
      if (incoming.kind !== "proposal") throw new Error("Expected proposal")
      expect(incoming.proposal.proposal).toStrictEqual(customProposal)
      return "accept"
    },
  })

  if (aliceProcessProposalResult.kind !== "newState") throw new Error("Expected new state")
  expect(aliceProcessProposalResult.aad).toStrictEqual(proposalAuthenticatedData)
  aliceGroup = aliceProcessProposalResult.newState

  const commitAuthenticatedData = encoder.encode("aad-commit")

  const aliceCommitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    authenticatedData: commitAuthenticatedData,
  })

  aliceGroup = aliceCommitResult.newState

  if (aliceCommitResult.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const tamperedCommit = {
    ...aliceCommitResult.commit.privateMessage,
    authenticatedData: encoder.encode("aad-commit-tampered"),
  }
  await expect(
    processPrivateMessageEnsureNoMutation({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: bobGroup,
      privateMessage: tamperedCommit,
      callback: () => {
        throw new Error("Callback should not run for tampered authenticatedData")
      },
    }),
  ).rejects.toThrow(CryptoError)

  const bobProcessCommitResult = await processPrivateMessageEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    privateMessage: aliceCommitResult.commit.privateMessage,
    callback: (incoming) => {
      if (incoming.kind !== "commit") throw new Error("Expected commit")
      expect(incoming.proposals.map((p) => p.proposal)).toStrictEqual([customProposal])
      return "accept"
    },
  })

  if (bobProcessCommitResult.kind !== "newState") throw new Error("Expected new state")

  expect(bobProcessCommitResult.aad).toStrictEqual(commitAuthenticatedData)
  bobGroup = bobProcessCommitResult.newState

  const publicProposalAuthenticatedData = encoder.encode("aad-proposal-public")
  const customProposalPublic: Proposal = {
    proposalType: customProposalType,
    proposalData: encoder.encode("custom proposal data (public)"),
  }

  const bobProposalPublicResult = await createProposal({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    wireAsPublicMessage: true,
    proposal: customProposalPublic,
    authenticatedData: publicProposalAuthenticatedData,
  })

  bobGroup = bobProposalPublicResult.newState

  if (bobProposalPublicResult.message.wireformat !== wireformats.mls_public_message)
    throw new Error("Expected public message")

  const tamperedPublicProposal = {
    ...bobProposalPublicResult.message.publicMessage,
    content: {
      ...bobProposalPublicResult.message.publicMessage.content,
      authenticatedData: encoder.encode("aad-proposal-public-tampered"),
    },
  }

  await expect(
    processPublicMessage({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: aliceGroup,
      publicMessage: tamperedPublicProposal,
    }),
  ).rejects.toThrow(CryptoVerificationError)

  const aliceProcessPublicProposalResult = await processPublicMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    publicMessage: bobProposalPublicResult.message.publicMessage,
    callback: (incoming) => {
      if (incoming.kind !== "proposal") throw new Error("Expected proposal")
      expect(incoming.proposal.proposal).toStrictEqual(customProposalPublic)
      return "accept"
    },
  })

  expect(aliceProcessPublicProposalResult.aad).toStrictEqual(publicProposalAuthenticatedData)

  aliceGroup = aliceProcessPublicProposalResult.newState

  const publicCommitAuthenticatedData = encoder.encode("aad-commit-public")

  const alicePublicCommitResult = await createCommitEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    wireAsPublicMessage: true,
    authenticatedData: publicCommitAuthenticatedData,
  })

  aliceGroup = alicePublicCommitResult.newState

  if (alicePublicCommitResult.commit.wireformat !== wireformats.mls_public_message)
    throw new Error("Expected public message")

  const tamperedPublicCommit = {
    ...alicePublicCommitResult.commit.publicMessage,
    content: {
      ...alicePublicCommitResult.commit.publicMessage.content,
      authenticatedData: encoder.encode("aad-commit-public-tampered"),
    },
  }

  await expect(
    processPublicMessage({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: bobGroup,
      publicMessage: tamperedPublicCommit,
    }),
  ).rejects.toThrow(CryptoVerificationError)

  const bobProcessPublicCommitResult = await processPublicMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: bobGroup,
    publicMessage: alicePublicCommitResult.commit.publicMessage,
    callback: (incoming) => {
      if (incoming.kind !== "commit") throw new Error("Expected commit")
      expect(incoming.proposals.map((p) => p.proposal)).toStrictEqual([customProposalPublic])
      return "accept"
    },
  })

  expect(bobProcessPublicCommitResult.aad).toStrictEqual(publicCommitAuthenticatedData)

  bobGroup = bobProcessPublicCommitResult.newState

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
}
