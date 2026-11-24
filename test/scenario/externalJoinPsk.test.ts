import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { createGroup, joinGroup } from "../../src/clientState.js"
import { contentTypes } from "../../src/contentType.js"
import { createGroupInfoWithExternalPubAndRatchetTree, joinGroupExternal } from "../../src/createCommit.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { CryptoVerificationError, ValidationError } from "../../src/mlsError.js"
import { PskId, pskTypes } from "../../src/presharedkey.js"
import { proposalOrRefTypes } from "../../src/proposalOrRefType.js"
import { bytesToBase64 } from "../../src/util/byteArray.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"

async function setup(cipherSuite: CiphersuiteName, resync = false) {
  const impl = await getCiphersuiteImpl(cipherSuite)
  const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
  const alice = await generateKeyPackage({
    cipherSuite: impl,
    credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode("alice") },
  })
  const bob = await generateKeyPackage({
    cipherSuite: impl,
    credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode("bob") },
  })
  let aliceGroup = await createGroup({
    context,
    groupId: new TextEncoder().encode("external-join-with-psks"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })
  if (resync) {
    const added = await createCommitEnsureNoMutation({
      context,
      state: aliceGroup,
      extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
    })
    aliceGroup = added.newState
    await joinGroup({
      context,
      welcome: added.welcome!.welcome,
      keyPackage: bob.publicPackage,
      privateKeys: bob.privatePackage,
      ratchetTree: aliceGroup.ratchetTree,
    })
  }

  const psks = [2, 1].map(
    (id) =>
      ({
        psktype: pskTypes.external,
        pskId: new TextEncoder().encode(`psk-${id}`),
        pskNonce: impl.rng.randomBytes(impl.kdf.size),
      }) satisfies PskId,
  )
  // The map order differs from the proposal order, and an unselected key must not be mixed in.
  const externalPsks = Object.fromEntries(
    [...psks].reverse().map((psk) => [bytesToBase64(psk.pskId), impl.rng.randomBytes(impl.kdf.size)]),
  )
  externalPsks[bytesToBase64(new TextEncoder().encode("unused-psk"))] = impl.rng.randomBytes(impl.kdf.size)
  const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)
  const params = {
    context: { ...context, externalPsks },
    groupInfo,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    resync,
    psks,
  }
  return { impl, context, aliceGroup, params }
}

test.concurrent.each(Object.keys(ciphersuites))("External join with multiple PSKs %s", async (cs) => {
  const { impl, aliceGroup, params } = await setup(cs as CiphersuiteName)
  const joined = await joinGroupExternal(params)
  const content = joined.commit.publicMessage.content
  if (content.contentType !== contentTypes.commit) throw new Error("Expected commit")
  expect(content.commit.proposals).toHaveLength(1 + params.psks.length)
  expect(content.commit.proposals.slice(1)).toStrictEqual(
    params.psks.map((psk) => ({
      proposalOrRefType: proposalOrRefTypes.proposal,
      proposal: { proposalType: defaultProposalTypes.psk, psk: { preSharedKeyId: psk } },
    })),
  )
  const externalPsks = { ...params.context.externalPsks }
  delete externalPsks[bytesToBase64(new TextEncoder().encode("unused-psk"))]
  const processed = await processMessageEnsureNoMutation({
    context: { ...params.context, externalPsks },
    state: aliceGroup,
    message: joined.commit,
  })
  expect(processed.newState.keySchedule).toStrictEqual(joined.newState.keySchedule)
  await testEveryoneCanMessageEveryone([processed.newState, joined.newState], impl)
})

test.concurrent.each(Object.keys(ciphersuites))(
  "External resync includes Remove and PSK proposals and agrees on the epoch",
  async (cs) => {
    const { impl, aliceGroup, params } = await setup(cs as CiphersuiteName, true)
    const joined = await joinGroupExternal(params)
    const content = joined.commit.publicMessage.content
    if (content.contentType !== contentTypes.commit) throw new Error("Expected commit")
    expect(
      content.commit.proposals.map((p) =>
        p.proposalOrRefType === proposalOrRefTypes.proposal ? p.proposal.proposalType : undefined,
      ),
    ).toEqual([
      defaultProposalTypes.remove,
      defaultProposalTypes.external_init,
      defaultProposalTypes.psk,
      defaultProposalTypes.psk,
    ])
    const processed = await processMessageEnsureNoMutation({
      context: params.context,
      state: aliceGroup,
      message: joined.commit,
    })
    expect(processed.newState.keySchedule).toStrictEqual(joined.newState.keySchedule)
    await testEveryoneCanMessageEveryone([processed.newState, joined.newState], impl)
  },
)

test.concurrent.each(Object.keys(ciphersuites))(
  "External join rejects a selected PSK missing from the joiner's context",
  async (cs) => {
    const { params } = await setup(cs as CiphersuiteName)
    const externalPsks = { ...params.context.externalPsks }
    delete externalPsks[bytesToBase64(params.psks[1]!.pskId)]
    await expect(joinGroupExternal({ ...params, context: { ...params.context, externalPsks } })).rejects.toThrow(
      new ValidationError("Could not find pskId referenced in proposal"),
    )
  },
)

test.concurrent.each(Object.keys(ciphersuites))(
  "External PSK join is rejected by a member with a missing secret",
  async (cs) => {
    const { context, aliceGroup, params } = await setup(cs as CiphersuiteName)
    const joined = await joinGroupExternal(params)
    const externalPsks = { ...params.context.externalPsks }
    const id = bytesToBase64(params.psks[1]!.pskId)
    delete externalPsks[id]
    await expect(
      processMessageEnsureNoMutation({
        context: { ...context, externalPsks },
        state: aliceGroup,
        message: joined.commit,
      }),
    ).rejects.toThrow(new ValidationError("Could not find pskId referenced in proposal"))
  },
)

test.concurrent.each(Object.keys(ciphersuites))(
  "External PSK join is rejected by a member with a wrong secret",
  async (cs) => {
    const { context, aliceGroup, params } = await setup(cs as CiphersuiteName)
    const joined = await joinGroupExternal(params)
    const externalPsks = { ...params.context.externalPsks }
    const id = bytesToBase64(params.psks[1]!.pskId)
    externalPsks[id] = new Uint8Array(context.cipherSuite.kdf.size)
    await expect(
      processMessageEnsureNoMutation({
        context: { ...context, externalPsks },
        state: aliceGroup,
        message: joined.commit,
      }),
    ).rejects.toThrow(new CryptoVerificationError("Could not verify confirmation tag"))
  },
)

test.concurrent.each(Object.keys(ciphersuites))("External join rejects duplicate PSK IDs", async (cs) => {
  const { params } = await setup(cs as CiphersuiteName)
  await expect(joinGroupExternal({ ...params, psks: [params.psks[0]!, { ...params.psks[0]! }] })).rejects.toThrow(
    new ValidationError("Commit cannot contain multiple PreSharedKey proposals that reference the same PreSharedKeyID"),
  )
})

test.concurrent.each(Object.keys(ciphersuites))("External join rejects a PSK nonce of the wrong length", async (cs) => {
  const { params } = await setup(cs as CiphersuiteName)
  await expect(
    joinGroupExternal({ ...params, psks: [{ ...params.psks[0]!, pskNonce: new Uint8Array() }] }),
  ).rejects.toThrow(new ValidationError("PSK nonce must have length KDF.Nh"))
})
