import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { ClientState, clientStateEncoder, createGroup, getOwnLeafNode, joinGroup } from "../../src/clientState.js"
import { decode } from "../../src/codec/tlsDecoder.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { contentTypes } from "../../src/contentType.js"
import {
  createCommit,
  createGroupInfoWithExternalPubAndRatchetTree,
  joinGroupExternal,
} from "../../src/createCommit.js"
import { createProposal } from "../../src/createMessage.js"
import { CiphersuiteImpl, CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { createContentCommitSignature } from "../../src/framedContent.js"
import { greaseValues } from "../../src/grease.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { MlsFramedMessage, mlsMessageDecoder, mlsMessageEncoder, MlsPublicMessage } from "../../src/message.js"
import { protectPublicMessage } from "../../src/messageProtectionPublic.js"
import { ValidationError } from "../../src/mlsError.js"
import { processMessage } from "../../src/processMessages.js"
import { ProposalCustom } from "../../src/proposal.js"
import { proposalOrRefTypes } from "../../src/proposalOrRefType.js"
import { wireformats } from "../../src/wireformat.js"
import { testEveryoneCanMessageEveryone } from "../scenario/common.js"

const customTypes = [0x0008, 0x000a, 0xf000]
const unsupportedTypes = [...customTypes, greaseValues[0]]
const customProposal = (proposalType = 0xf000): ProposalCustom => ({ proposalType, proposalData: new Uint8Array([42]) })

test.concurrent.each(Object.keys(ciphersuites))("Custom proposal validation standalone %s", async (cs) => {
  await unsupportedStandaloneProposalTest(cs as CiphersuiteName)
})
test.concurrent.each(Object.keys(ciphersuites))("Custom proposal validation commit %s", async (cs) => {
  await unsupportedCommitProposalTest(cs as CiphersuiteName)
})

test.concurrent.each(Object.keys(ciphersuites))("Custom proposal validation membership exceptions %s", async (cs) => {
  await customProposalMembershipExceptionsTest(cs as CiphersuiteName)
})
test.concurrent.each(Object.keys(ciphersuites))("Custom proposal validation external commit fails %s", async (cs) => {
  await externalCommitCustomProposalTest(cs as CiphersuiteName)
})

async function setup(cipherSuite: CiphersuiteName, aliceTypes: number[], bobTypes: number[]) {
  const impl = await getCiphersuiteImpl(cipherSuite)
  const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
  const makeKeyPackage = (identity: string, proposals: number[]) =>
    generateKeyPackage({
      cipherSuite: impl,
      credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode(identity) },
      capabilities: { ...defaultCapabilities(), proposals },
    })
  const alice = await makeKeyPackage("alice", aliceTypes)
  const bob = await makeKeyPackage("bob", bobTypes)
  const group = await createGroup({
    context,
    groupId: new TextEncoder().encode("custom-proposal-validation"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })
  const added = await createCommit({
    context,
    state: group,
    extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
  })
  const aliceGroup = added.newState
  const bobGroup = await joinGroup({
    context,
    welcome: added.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })
  return { context, aliceGroup, bobGroup, makeKeyPackage }
}

async function unsupportedStandaloneProposalTest(cipherSuite: CiphersuiteName) {
  // GREASE in capabilities must not be mistaken for support for an actual proposal.
  const { context, aliceGroup, bobGroup } = await setup(cipherSuite, [greaseValues[0]], unsupportedTypes)
  const before = encode(clientStateEncoder, aliceGroup)
  for (const proposalType of unsupportedTypes) {
    for (const wireAsPublicMessage of [false, true]) {
      const proposed = await createProposal({
        context,
        state: bobGroup,
        wireAsPublicMessage,
        proposal: customProposal(proposalType),
      })
      await expect(processMessage({ context, state: aliceGroup, message: proposed.message })).rejects.toThrow(
        new ValidationError(`Unsupported proposal type: ${proposalType}`),
      )
      expect(encode(clientStateEncoder, aliceGroup)).toStrictEqual(before)
    }
  }
}

async function unsupportedCommitProposalTest(cipherSuite: CiphersuiteName) {
  const { context, aliceGroup, bobGroup } = await setup(cipherSuite, unsupportedTypes, [greaseValues[0]])
  const aliceBefore = encode(clientStateEncoder, aliceGroup)
  const bobBefore = encode(clientStateEncoder, bobGroup)
  const valid = await createCommit({ context, state: aliceGroup, wireAsPublicMessage: true })
  for (const proposalType of unsupportedTypes) {
    const proposal = customProposal(proposalType)
    const error = new ValidationError(`Proposal type ${proposalType} is not supported by all continuing members`)
    await expect(createCommit({ context, state: aliceGroup, extraProposals: [proposal] })).rejects.toThrow(error)

    const proposed = await createProposal({ context, state: aliceGroup, proposal })
    await expect(createCommit({ context, state: proposed.newState })).rejects.toThrow(error)

    // Authenticate the malformed list so rejection must happen before checking the reused confirmation tag.
    const message = await appendAndResignProposal(aliceGroup, valid.commit, proposal, context.cipherSuite)
    const callback = vi.fn(() => "accept" as const)
    await expect(processMessage({ context, state: bobGroup, message, callback })).rejects.toThrow(error)
    expect(callback).not.toHaveBeenCalled()
    expect(encode(clientStateEncoder, aliceGroup)).toStrictEqual(aliceBefore)
    expect(encode(clientStateEncoder, bobGroup)).toStrictEqual(bobBefore)
  }

  // Advertising support in this Commit's UpdatePath cannot make its previously unsupported type valid.
  const patched = await createCommit({
    context,
    state: bobGroup,
    wireAsPublicMessage: true,
    leafNodePatch: { capabilities: { ...getOwnLeafNode(bobGroup).capabilities, proposals: customTypes } },
  })
  const message = await appendAndResignProposal(bobGroup, patched.commit, customProposal(), context.cipherSuite)
  await expect(processMessage({ context, state: aliceGroup, message })).rejects.toThrow(
    new ValidationError("Proposal type 61440 is not supported by all continuing members"),
  )
  expect(encode(clientStateEncoder, aliceGroup)).toStrictEqual(aliceBefore)
}

async function customProposalMembershipExceptionsTest(cipherSuite: CiphersuiteName) {
  const { context, aliceGroup, bobGroup, makeKeyPackage } = await setup(cipherSuite, [0xf000], [0xf000])
  const charlie = await makeKeyPackage("charlie", [])
  // A newly added member receives a Welcome and does not process this proposal.
  const added = await createCommit({
    context,
    state: aliceGroup,
    extraProposals: [
      customProposal(),
      { proposalType: defaultProposalTypes.add, add: { keyPackage: charlie.publicPackage } },
    ],
  })
  const updatedBob = await processMessage({ context, state: bobGroup, message: added.commit })
  const joined = await joinGroup({
    context,
    welcome: added.welcome!.welcome,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
    ratchetTree: added.newState.ratchetTree,
  })
  expect(joined.keySchedule.epochAuthenticator).toStrictEqual(added.newState.keySchedule.epochAuthenticator)

  // A removed member is also exempt even when its Remove follows the custom proposal
  const committed = await createCommit({
    context,
    state: added.newState,
    extraProposals: [
      customProposal(),
      { proposalType: defaultProposalTypes.remove, remove: { removed: joined.privatePath.leafIndex } },
    ],
  })
  const removed = await processMessage({ context, state: joined, message: committed.commit })
  expect(removed.newState.groupActiveState.kind).toBe("removedFromGroup")
  const continued = await processMessage({ context, state: updatedBob.newState, message: committed.commit })
  await testEveryoneCanMessageEveryone([committed.newState, continued.newState], context.cipherSuite)
}

async function externalCommitCustomProposalTest(cipherSuite: CiphersuiteName) {
  const { context, aliceGroup, makeKeyPackage } = await setup(cipherSuite, customTypes, customTypes)
  const charlie = await makeKeyPackage("charlie", customTypes)
  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], context.cipherSuite)
  const joined = await joinGroupExternal({
    context,
    groupInfo,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
    resync: false,
  })
  const before = encode(clientStateEncoder, aliceGroup)
  for (const proposalType of customTypes) {
    const message = await appendAndResignProposal(
      aliceGroup,
      joined.commit,
      customProposal(proposalType),
      context.cipherSuite,
      joined.newState.signaturePrivateKey,
    )
    await expect(processMessage({ context, state: aliceGroup, message })).rejects.toThrow(
      new ValidationError("ExternalInit cannot have non-default proposals"),
    )
    expect(encode(clientStateEncoder, aliceGroup)).toStrictEqual(before)
  }
}

async function appendAndResignProposal(
  state: ClientState,
  message: MlsFramedMessage,
  proposal: ProposalCustom,
  cs: CiphersuiteImpl,
  signKey = state.signaturePrivateKey,
): Promise<MlsPublicMessage> {
  if (message.wireformat !== wireformats.mls_public_message) throw new Error("Expected public commit")
  const { content, auth } = message.publicMessage
  if (content.contentType !== contentTypes.commit) throw new Error("Expected commit")
  const { framedContent, signature } = await createContentCommitSignature(
    state.groupContext,
    "mls_public_message",
    {
      ...content.commit,
      proposals: [...content.commit.proposals, { proposalOrRefType: proposalOrRefTypes.proposal, proposal }],
    },
    content.sender,
    content.authenticatedData,
    signKey,
    cs.signature,
  )
  const publicMessage = await protectPublicMessage(
    state.keySchedule.membershipKey,
    state.groupContext,
    { wireformat: wireformats.mls_public_message, content: framedContent, auth: { ...auth, signature } },
    cs,
  )
  const decoded = decode(mlsMessageDecoder, encode(mlsMessageEncoder, { ...message, publicMessage }))
  if (decoded?.wireformat !== wireformats.mls_public_message) throw new Error("Could not decode public commit")
  return decoded
}
