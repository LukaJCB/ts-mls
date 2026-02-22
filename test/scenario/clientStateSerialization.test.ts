import {
  CiphersuiteName,
  ciphersuites,
  createGroup,
  Credential,
  defaultCredentialTypes,
  generateKeyPackage,
  getCiphersuiteImpl,
  Proposal,
  createApplicationMessage,
  defaultProposalTypes,
  encode,
  unsafeTestingAuthenticationService,
  clientStateEncoder,
  clientStateDecoder,
} from "../../src/index.js"
import { createCommitEnsureNoMutation } from "./common.js"

test.concurrent.each(Object.keys(ciphersuites))("ClientState Binary serialization round-trip %s", async (cs) => {
  await clientStateBinarySerializationTest(cs as CiphersuiteName)
})

async function clientStateBinarySerializationTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }

  const alice = await generateKeyPackage({
    credential: aliceCredential,
    cipherSuite: impl,
  })

  const groupId = new TextEncoder().encode("test-group")

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const binary = encode(clientStateEncoder, aliceGroup)
  expect(binary).toBeInstanceOf(Uint8Array)
  expect(binary.byteLength).toBeGreaterThan(0)

  const decoded = clientStateDecoder(binary, 0)

  if (!decoded) {
    throw new Error("binary deserialization failed unexpectedly")
  }

  expect(aliceGroup).toEqual(decoded[0])

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({
    credential: bobCredential,
    cipherSuite: impl,
  })

  const charlieCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("charlie"),
  }
  const charlie = await generateKeyPackage({
    credential: charlieCredential,
    cipherSuite: impl,
  })

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

  const addBobAndCharlieCommitResult = await createCommitEnsureNoMutation({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [addBobProposal, addCharlieProposal],
  })

  aliceGroup = addBobAndCharlieCommitResult.newState

  const message = new TextEncoder().encode("Hello!")

  const aliceCreateMessageResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: aliceGroup,
    message,
  })

  aliceGroup = aliceCreateMessageResult.newState

  const binary2 = encode(clientStateEncoder, aliceGroup)

  const decoded2 = clientStateDecoder(binary2, 0)

  if (!decoded2) {
    throw new Error("binary deserialization failed unexpectedly")
  }

  expect(aliceGroup).toEqual(decoded2[0])
}
