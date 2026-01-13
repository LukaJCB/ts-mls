import {
  CiphersuiteName,
  ciphersuites,
  createCommit,
  createGroup,
  Credential,
  defaultCapabilities,
  defaultCredentialTypes,
  defaultLifetime,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  Proposal,
  decodeGroupState,
  createApplicationMessage,
  defaultProposalTypes,
  groupStateEncoder,
  encode,
} from "../../src/index.js"

test.concurrent.each(Object.keys(ciphersuites))("ClientState Binary serialization round-trip %s", async (cs) => {
  await clientStateBinarySerializationTest(cs as CiphersuiteName)
})

async function clientStateBinarySerializationTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }

  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("test-group")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const { clientConfig: _config, ...firstState } = aliceGroup

  const binary = encode(groupStateEncoder, aliceGroup)
  expect(binary).toBeInstanceOf(Uint8Array)
  expect(binary.byteLength).toBeGreaterThan(0)

  const decoded = decodeGroupState(binary, 0)

  if (!decoded) {
    throw new Error("binary deserialization failed unexpectedly")
  }

  expect(firstState).toEqual(decoded[0])

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addCharlieProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: charlie.publicPackage,
    },
  }

  const addBobAndCharlieCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    {
      extraProposals: [addBobProposal, addCharlieProposal],
    },
  )

  aliceGroup = addBobAndCharlieCommitResult.newState

  const message = new TextEncoder().encode("Hello!")

  const aliceCreateMessageResult = await createApplicationMessage(aliceGroup, message, impl)

  aliceGroup = aliceCreateMessageResult.newState

  const { clientConfig: _config2, ...secondState } = aliceGroup

  const binary2 = encode(groupStateEncoder, aliceGroup)

  const decoded2 = decodeGroupState(binary2, 0)

  if (!decoded2) {
    throw new Error("binary deserialization failed unexpectedly")
  }

  expect(secondState).toEqual(decoded2[0])
}
