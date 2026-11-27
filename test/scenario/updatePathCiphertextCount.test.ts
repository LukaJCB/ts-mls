import { createGroup, joinGroup, nextEpochContext } from "../../src/clientState.js"
import { applyUpdatePathSecret, createCommit } from "../../src/createCommit.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { createConfirmationTag, createContentCommitSignature } from "../../src/framedContent.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { initializeEpoch } from "../../src/keySchedule.js"
import { ValidationError } from "../../src/mlsError.js"
import { getCommitSecret } from "../../src/pathSecrets.js"
import { processMessage } from "../../src/processMessages.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { contentTypes } from "../../src/contentType.js"
import { protectPublicMessage } from "../../src/messageProtectionPublic.js"
import { leafToNodeIndex, toLeafIndex } from "../../src/treemath.js"
import { UpdatePath } from "../../src/updatePath.js"
import { wireformats } from "../../src/wireformat.js"

async function setup(addDuringUpdate = false) {
  const impl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
  const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
  const makeMember = (identity: string) =>
    generateKeyPackage({
      credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode(identity) },
      cipherSuite: impl,
    })
  const [alice, bob, charlie] = await Promise.all([makeMember("alice"), makeMember("bob"), makeMember("charlie")])
  const initial = await createGroup({
    context,
    groupId: new TextEncoder().encode("update-path-ciphertext-count"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })
  const added = await createCommit({
    context,
    state: initial,
    extraProposals: (addDuringUpdate ? [bob] : [bob, charlie]).map((member) => ({
      proposalType: defaultProposalTypes.add,
      add: { keyPackage: member.publicPackage },
    })),
  })
  const aliceGroup = added.newState
  const join = (member: typeof bob) =>
    joinGroup({
      context,
      welcome: added.welcome!.welcome,
      keyPackage: member.publicPackage,
      privateKeys: member.privatePackage,
      ratchetTree: aliceGroup.ratchetTree,
    })
  const bobGroup = await join(bob)
  const recipients = addDuringUpdate ? [bobGroup] : [bobGroup, await join(charlie)]
  const created = await createCommit({
    context,
    state: aliceGroup,
    leafNodePatch: {},
    wireAsPublicMessage: true,
    extraProposals: addDuringUpdate
      ? [{ proposalType: defaultProposalTypes.add, add: { keyPackage: charlie.publicPackage } }]
      : [],
  })
  const message = created.commit
  if (message.wireformat !== wireformats.mls_public_message) throw new Error("Expected public message")
  const { content } = message.publicMessage
  if (content.contentType !== contentTypes.commit || content.commit.path === undefined)
    throw new Error("Expected UpdatePath")
  const originalPath = content.commit.path
  expect(originalPath.nodes.map((node) => node.encryptedPathSecret.length)).toStrictEqual(
    addDuringUpdate ? [1, 0] : [1, 1],
  )

  const decrypted = await applyUpdatePathSecret(
    created.newState.ratchetTree,
    bobGroup.privatePath,
    toLeafIndex(aliceGroup.privatePath.leafIndex),
    {
      ...aliceGroup.groupContext,
      epoch: aliceGroup.groupContext.epoch + 1n,
      treeHash: created.newState.groupContext.treeHash,
    },
    originalPath,
    addDuringUpdate ? [leafToNodeIndex(toLeafIndex(2))] : [],
    impl,
  )
  const commitSecret = await getCommitSecret(
    created.newState.ratchetTree,
    decrypted.nodeIndex,
    decrypted.pathSecret,
    impl.kdf,
  )

  // Authenticate every modified path completely, including its changed transcript and confirmation tag.
  const authenticate = async (path: UpdatePath) => {
    const { framedContent, signature } = await createContentCommitSignature(
      aliceGroup.groupContext,
      "mls_public_message",
      { ...content.commit, path },
      content.sender,
      content.authenticatedData,
      aliceGroup.signaturePrivateKey,
      impl.signature,
    )
    const groupContext = await nextEpochContext(
      aliceGroup.groupContext,
      "mls_public_message",
      framedContent,
      signature,
      created.newState.groupContext.treeHash,
      aliceGroup.confirmationTag,
      impl.hash,
    )
    const epoch = await initializeEpoch(
      aliceGroup.keySchedule.initSecret,
      commitSecret,
      groupContext,
      new Uint8Array(impl.kdf.size),
      impl.kdf,
    )
    const confirmationTag = await createConfirmationTag(
      epoch.keySchedule.confirmationKey,
      groupContext.confirmedTranscriptHash,
      impl.hash,
    )
    const publicMessage = await protectPublicMessage(
      aliceGroup.keySchedule.membershipKey,
      aliceGroup.groupContext,
      {
        wireformat: wireformats.mls_public_message,
        content: framedContent,
        auth: { contentType: contentTypes.commit, signature, confirmationTag },
      },
      impl,
    )
    return { ...message, publicMessage }
  }
  return { context, recipients, created, originalPath, authenticate, charlie }
}

test.each([
  { node: 0, change: "missing" },
  { node: 1, change: "missing" },
  { node: 0, change: "extra" },
  { node: 1, change: "extra" },
])("all recipients reject a $change ciphertext at path node $node", async ({ node, change }) => {
  const { context, recipients, originalPath, authenticate } = await setup()
  const path = structuredClone(originalPath)
  const ciphertexts = path.nodes[node]!.encryptedPathSecret
  if (change === "missing") ciphertexts.pop()
  else ciphertexts.push(structuredClone(ciphertexts[0]!))
  const message = await authenticate(path)

  for (const state of recipients) {
    const before = structuredClone(state)
    await expect(processMessage({ context, state, message }).then(() => "accepted")).rejects.toThrow(ValidationError)
    expect(state).toStrictEqual(before)
  }
})

test.each([false, true])(
  "accepts correct counts including exclusions for newly added leaves (Add: %s)",
  async (add) => {
    const { context, recipients, created, charlie } = await setup(add)
    for (const state of recipients) {
      const processed = await processMessage({ context, state, message: created.commit })
      expect(processed.newState.keySchedule.epochAuthenticator).toStrictEqual(
        created.newState.keySchedule.epochAuthenticator,
      )
    }
    if (add) {
      const joined = await joinGroup({
        context,
        welcome: created.welcome!.welcome,
        keyPackage: charlie.publicPackage,
        privateKeys: charlie.privatePackage,
        ratchetTree: created.newState.ratchetTree,
      })
      expect(joined.privatePath.leafIndex).toBe(2)
      expect(joined.keySchedule.epochAuthenticator).toStrictEqual(created.newState.keySchedule.epochAuthenticator)
    }
  },
)

test("applyUpdatePathSecret rejects a truncated ciphertext list", async () => {
  const { context, recipients, created, originalPath } = await setup()
  const path = structuredClone(originalPath)
  path.nodes[0]!.encryptedPathSecret.pop()

  await expect(
    applyUpdatePathSecret(
      created.newState.ratchetTree,
      recipients[0]!.privatePath,
      toLeafIndex(created.newState.privatePath.leafIndex),
      created.newState.groupContext,
      path,
      [],
      context.cipherSuite,
    ),
  ).rejects.toThrow(new ValidationError("UpdatePathNode encrypted path secret count mismatch"))
})

test("rejects ciphertexts for a path node whose recipients are all newly added leaves", async () => {
  const { context, recipients, originalPath, authenticate } = await setup(true)
  const path = structuredClone(originalPath)
  path.nodes[1]!.encryptedPathSecret.push(structuredClone(path.nodes[0]!.encryptedPathSecret[0]!))
  const message = await authenticate(path)
  await expect(processMessage({ context, state: recipients[0]!, message }).then(() => "accepted")).rejects.toThrow(
    ValidationError,
  )
})
