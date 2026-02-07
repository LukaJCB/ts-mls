import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { testEveryoneCanMessageEveryone } from "./common.js"
import { Capabilities } from "../../src/capabilities.js"
import {
  createApplicationMessage,
  createProposal,
  processMessage,
  processPrivateMessage,
  unsafeTestingAuthenticationService,
} from "../../src/index.js"
import { UsageError } from "../../src/mlsError.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"

test.concurrent.each(Object.keys(ciphersuites))(`Custom Proposals %s`, async (cs) => {
  await customProposalTest(cs as CiphersuiteName)
})

async function customProposalTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

  const customProposalType: number = 8

  const capabilities: Capabilities = {
    extensions: [],
    credentials: [defaultCredentialTypes.basic],
    proposals: [customProposalType],
    versions: [protocolVersions.mls10],
    ciphersuites: [ciphersuites[cipherSuite]],
  }

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

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({
    credential: bobCredential,
    capabilities,
    cipherSuite: impl,
  })

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [addBobProposal],
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

  const proposalData = new TextEncoder().encode("custom proposal data")

  const customProposal: Proposal = {
    proposalType: 8,
    proposalData: proposalData,
  }

  const createProposalResult = await createProposal({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    wireAsPublicMessage: false,
    proposal: customProposal,
  })

  bobGroup = createProposalResult.newState

  if (createProposalResult.message.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const processProposalResult = await processMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    message: createProposalResult.message,
    callback: (p) => {
      if (p.kind !== "proposal") throw new Error("Expected proposal")
      expect(p.proposal.proposal).toStrictEqual(customProposal)
      return "accept"
    },
  })

  aliceGroup = processProposalResult.newState

  //creating an application message will fail now
  await expect(
    createApplicationMessage({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      message: new Uint8Array([1, 2, 3]),
    }),
  ).rejects.toThrow(UsageError)

  const createCommitResult = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
  })

  aliceGroup = createCommitResult.newState

  if (createCommitResult.commit.wireformat !== wireformats.mls_private_message)
    throw new Error("Expected private message")

  const processCommitResult = await processPrivateMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: bobGroup,
    privateMessage: createCommitResult.commit.privateMessage,
    callback: (p) => {
      if (p.kind !== "commit") throw new Error("Expected commit")
      expect(p.proposals.map((p) => p.proposal)).toStrictEqual([customProposal])
      return "accept"
    },
  })

  bobGroup = processCommitResult.newState

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}
