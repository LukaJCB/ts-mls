import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { defaultClientConfig } from "../../src/clientConfig.js"
import { clientStateEncoder, createGroup, joinGroup } from "../../src/clientState.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { createCommit } from "../../src/createCommit.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Lifetime, validateLifetime } from "../../src/lifetime.js"
import { ValidationError } from "../../src/mlsError.js"
import { processKeyPackage, processMessage } from "../../src/processMessages.js"
import { ProposalAdd } from "../../src/proposal.js"
import { wireformats } from "../../src/wireformat.js"

test.concurrent.each(Object.keys(ciphersuites))("Maximum total lifetime %s", async (cs) => {
  await maximumTotalLifetimeTest(cs as CiphersuiteName)
})

async function maximumTotalLifetimeTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(cipherSuite)
  const maximumTotalLifetime = 3600n
  const now = BigInt(Math.floor(Date.now() / 1000))
  const lifetime: Lifetime = { notBefore: now - 600n, notAfter: now + 3000n }
  const context = {
    cipherSuite: impl,
    authService: unsafeTestingAuthenticationService,
    clientConfig: {
      ...defaultClientConfig,
      lifetimeConfig: { maximumTotalLifetime, validateLifetimeOnReceive: false },
    },
  }
  const makeKeyPackage = (identity: string, validity = lifetime) =>
    generateKeyPackage({
      cipherSuite: impl,
      credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode(identity) },
      lifetime: validity,
    })
  const alice = await makeKeyPackage("alice")
  const bob = await makeKeyPackage("bob")
  const initialGroup = await createGroup({
    context,
    groupId: new TextEncoder().encode("maximum-lifetime"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })
  const addedBob = await createCommit({
    context,
    state: initialGroup,
    extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
  })
  const aliceGroup = addedBob.newState
  const bobGroup = await joinGroup({
    context,
    welcome: addedBob.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })
  const overlong = await makeKeyPackage("charlie", { ...lifetime, notAfter: lifetime.notAfter + 1n })
  const reversed = await makeKeyPackage("charlie", { notBefore: lifetime.notAfter, notAfter: lifetime.notBefore })
  const boundary = await makeKeyPackage("diana")
  const overlongAdd: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: overlong.publicPackage },
  }
  // A sender with a more permissive policy can produce an otherwise valid Commit and Welcome.
  const permissive = {
    ...context,
    clientConfig: {
      ...context.clientConfig,
      lifetimeConfig: { maximumTotalLifetime: 3601n, validateLifetimeOnReceive: false },
    },
  }
  const overlongCommit = await createCommit({ context: permissive, state: aliceGroup, extraProposals: [overlongAdd] })
  expect(overlongCommit.commit.wireformat).toBe(wireformats.mls_private_message)
  const bobBefore = encode(clientStateEncoder, bobGroup)

  for (const validateLifetimeOnReceive of [false, true]) {
    const strict = {
      ...context,
      clientConfig: { ...context.clientConfig, lifetimeConfig: { maximumTotalLifetime, validateLifetimeOnReceive } },
    }
    const error = new ValidationError("Lifetime exceeds maximum total lifetime")
    await expect(
      processKeyPackage({ context: strict, state: aliceGroup, keyPackage: overlong.publicPackage }),
    ).rejects.toThrow(error)
    await expect(createCommit({ context: strict, state: aliceGroup, extraProposals: [overlongAdd] })).rejects.toThrow(
      error,
    )
    await expect(processMessage({ context: strict, state: bobGroup, message: overlongCommit.commit })).rejects.toThrow(
      error,
    )
    expect(encode(clientStateEncoder, bobGroup)).toStrictEqual(bobBefore)
    await expect(
      joinGroup({
        context: strict,
        welcome: overlongCommit.welcome!.welcome,
        keyPackage: overlong.publicPackage,
        privateKeys: overlong.privatePackage,
        ratchetTree: overlongCommit.newState.ratchetTree,
      }),
    ).rejects.toThrow(error)

    const reversedError = new ValidationError("Lifetime notAfter must not be before notBefore")
    await expect(
      processKeyPackage({ context: strict, state: aliceGroup, keyPackage: reversed.publicPackage }),
    ).rejects.toThrow(reversedError)
    await expect(
      createCommit({
        context: strict,
        state: aliceGroup,
        extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: reversed.publicPackage } }],
      }),
    ).rejects.toThrow(reversedError)

    // Exactly the configured maximum remains valid in both validation paths.
    const proposal = await processKeyPackage({ context: strict, state: aliceGroup, keyPackage: boundary.publicPackage })
    const committed = await createCommit({ context: strict, state: aliceGroup, extraProposals: [proposal] })
    const received = await processMessage({ context: strict, state: bobGroup, message: committed.commit })
    const joined = await joinGroup({
      context: strict,
      welcome: committed.welcome!.welcome,
      keyPackage: boundary.publicPackage,
      privateKeys: boundary.privatePackage,
      ratchetTree: committed.newState.ratchetTree,
    })
    expect(received.newState.keySchedule.epochAuthenticator).toStrictEqual(
      committed.newState.keySchedule.epochAuthenticator,
    )
    expect(joined.keySchedule.epochAuthenticator).toStrictEqual(committed.newState.keySchedule.epochAuthenticator)
  }
}

test.each([false, true])("Expiration checks on receive remain optional: %s", (validateLifetimeOnReceive) => {
  const now = BigInt(Math.floor(Date.now() / 1000))
  const lifetime = { notBefore: now - 3600n, notAfter: now - 60n }
  const config = { maximumTotalLifetime: 3600n, validateLifetimeOnReceive }
  expect(validateLifetime(lifetime, config, false)).toEqual(
    validateLifetimeOnReceive ? new ValidationError("Current time not within Lifetime") : undefined,
  )
  expect(validateLifetime(lifetime, config, true)).toEqual(new ValidationError("Current time not within Lifetime"))
})

test("A zero maximum permits only zero-duration lifetimes", () => {
  const config = { maximumTotalLifetime: 0n, validateLifetimeOnReceive: false }
  expect(validateLifetime({ notBefore: 1n, notAfter: 1n }, config, false)).toBeUndefined()
  expect(validateLifetime({ notBefore: 1n, notAfter: 2n }, config, false)).toEqual(
    new ValidationError("Lifetime exceeds maximum total lifetime"),
  )
})
