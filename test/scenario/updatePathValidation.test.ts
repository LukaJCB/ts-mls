import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { CryptoVerificationError } from "../../src/mlsError.js"
import { processMessage } from "../../src/processMessages.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { encryptWithLabel } from "../../src/crypto/hpke.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { groupContextEncoder } from "../../src/groupContext.js"
import { contentTypes } from "../../src/contentType.js"
import { createContentCommitSignature } from "../../src/framedContent.js"
import { protectPublicMessage } from "../../src/messageProtectionPublic.js"
import { wireformats } from "../../src/wireformat.js"

test("rejects an authenticated UpdatePath whose encrypted secret does not match its public key", async () => {
  const impl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
  const context = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
  const makeMember = (identity: string) =>
    generateKeyPackage({
      credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode(identity) },
      cipherSuite: impl,
    })
  const alice = await makeMember("alice")
  const bob = await makeMember("bob")
  const initialGroup = await createGroup({
    context,
    groupId: new TextEncoder().encode("update-path-validation"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })
  const addBob = await createCommit({
    context,
    state: initialGroup,
    extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
  })
  const aliceGroup = addBob.newState
  const bobGroup = await joinGroup({
    context,
    welcome: addBob.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })
  const previousPrivateKeys = structuredClone(bobGroup.privatePath)

  const update = await createCommit({
    context,
    state: aliceGroup,
    leafNodePatch: {},
    wireAsPublicMessage: true,
  })

  if (update.commit.wireformat !== wireformats.mls_public_message) throw new Error("Expected public message")
  const { content, auth } = update.commit.publicMessage
  if (content.contentType !== contentTypes.commit) throw new Error("Expected commit")
  const pathNode = content.commit.path?.nodes[0]
  if (pathNode === undefined) throw new Error("Expected UpdatePath node")

  // Replace Bob's encrypted path secret without changing the advertised public key.
  const provisionalContext = {
    ...aliceGroup.groupContext,
    epoch: aliceGroup.groupContext.epoch + 1n,
    treeHash: update.newState.groupContext.treeHash,
  }
  const { ct, enc } = await encryptWithLabel(
    await impl.hpke.importPublicKey(bob.publicPackage.leafNode.hpkePublicKey),
    "UpdatePathNode",
    encode(groupContextEncoder, provisionalContext),
    impl.rng.randomBytes(impl.kdf.size),
    impl.hpke,
  )
  pathNode.encryptedPathSecret[0] = { ciphertext: ct, kemOutput: enc }

  const { framedContent, signature } = await createContentCommitSignature(
    aliceGroup.groupContext,
    "mls_public_message",
    content.commit,
    content.sender,
    content.authenticatedData,
    aliceGroup.signaturePrivateKey,
    impl.signature,
  )
  // Refresh the signature and membership tag so rejection occurs at the derived-key check,
  // before the reused confirmation tag is checked.
  const publicMessage = await protectPublicMessage(
    aliceGroup.keySchedule.membershipKey,
    aliceGroup.groupContext,
    { wireformat: wireformats.mls_public_message, content: framedContent, auth: { ...auth, signature } },
    impl,
  )

  await expect(
    processMessage({ context, state: bobGroup, message: { ...update.commit, publicMessage } }),
  ).rejects.toThrow(new CryptoVerificationError("Derived public key does not match the ratchet tree"))
  expect(bobGroup.privatePath).toStrictEqual(previousPrivateKeys)
})
