import json from "../../test_vectors/message-protection.json"
import { hexToBytes } from "@noble/ciphers/utils.js"
import { GroupContext } from "../../src/groupContext.js"
import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { decodeMlsMessage } from "../../src/message.js"
import { protect, unprotectPrivateMessage } from "../../src/messageProtection.js"
import { createContentCommitSignature } from "../../src/framedContent.js"
import { decodeProposal, encodeProposal } from "../../src/proposal.js"
import { decodeCommit, encodeCommit } from "../../src/commit.js"
import { AuthenticatedContent } from "../../src/authenticatedContent.js"
import { createSecretTree } from "../../src/secretTree.js"
import { protectApplicationData, protectProposal } from "../../src/messageProtection.js"
import {
  protectProposalPublic,
  protectPublicMessage,
  unprotectPublicMessage,
} from "../../src/messageProtectionPublic.js"
import { defaultKeyRetentionConfig } from "../../src/keyRetentionConfig.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { RatchetTree } from "../../src/ratchetTree.js"
import { UsageError } from "../../src/mlsError.js"
import { defaultPaddingConfig } from "../../src/paddingConfig.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { leafNodeSources } from "../../src/leafNodeSource.js"
import { nodeTypes } from "../../src/nodeType.js"
import { contentTypes } from "../../src/contentType.js"
import { senderTypes } from "../../src/sender.js"
import { wireformats } from "../../src/wireformat.js"

test.concurrent.each(json.map((x, index) => [index, x]))(`message-protection test vectors %i`, async (_index, x) => {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
  await testMessageProtection(x, impl)
})

type MessageProtectionData = {
  cipher_suite: number
  group_id: string
  epoch: number
  tree_hash: string
  confirmed_transcript_hash: string
  signature_priv: string
  signature_pub: string
  encryption_secret: string
  sender_data_secret: string
  membership_key: string
  proposal: string
  proposal_priv: string
  proposal_pub: string
  commit: string
  commit_priv: string
  commit_pub: string
  application: string
  application_priv: string
}

async function testMessageProtection(data: MessageProtectionData, impl: CiphersuiteImpl) {
  const gc: GroupContext = {
    version: protocolVersions.mls10,
    cipherSuite: data.cipher_suite as CiphersuiteId,
    groupId: hexToBytes(data.group_id),
    epoch: BigInt(data.epoch),
    treeHash: hexToBytes(data.tree_hash),
    confirmedTranscriptHash: hexToBytes(data.confirmed_transcript_hash),
    extensions: [],
  }

  await publicProposal(data, gc, impl)
  await protectThenUnprotectProposalPublic(data, gc, impl)

  await publicCommit(data, gc, impl)
  await protectThenUnprotectCommitPublic(data, gc, impl)

  await proposal(data, gc, impl)
  await protectThenUnprotectProposal(data, gc, impl)

  await application(data, gc, impl)
  await protectThenUnprotectApplication(data, gc, impl)

  await commit(data, gc, impl)
  await protectThenUnprotectCommit(data, gc, impl)

  await publicApplicationFails(data, gc, impl)
}

// need to provide a ratchet tree with non blank leaf node so senderData validation doesn't fail
const treeForLeafIndex1: RatchetTree = [
  undefined,
  undefined,
  {
    nodeType: nodeTypes.leaf,
    leaf: {
      leafNodeSource: leafNodeSources.commit,
      hpkePublicKey: new Uint8Array(),
      signaturePublicKey: new Uint8Array(),
      capabilities: defaultCapabilities(),
      parentHash: new Uint8Array(),
      extensions: [],
      signature: new Uint8Array(),
      credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array() },
    },
  },
]

async function protectThenUnprotectProposalPublic(
  data: MessageProtectionData,
  gc: GroupContext,
  impl: CiphersuiteImpl,
) {
  const p = decodeProposal(hexToBytes(data.proposal), 0)
  if (p === undefined) throw new Error("could not decode proposal")

  const prot = await protectProposalPublic(
    hexToBytes(data.signature_priv),
    hexToBytes(data.membership_key),
    gc,
    new Uint8Array(),
    p[0],
    1,
    impl,
  )

  const unprotected = await unprotectPublicMessage(
    hexToBytes(data.membership_key),
    gc,
    [],
    prot.publicMessage,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected === undefined || unprotected.content.contentType !== contentTypes.proposal)
    throw new Error("could not unprotect mls public message")

  expect(encodeProposal(unprotected.content.proposal)).toStrictEqual(hexToBytes(data.proposal))
}

async function protectThenUnprotectCommitPublic(data: MessageProtectionData, gc: GroupContext, impl: CiphersuiteImpl) {
  const c = decodeCommit(hexToBytes(data.commit), 0)
  if (c === undefined) throw new Error("could not decode commit")

  const confirmationTag = crypto.getRandomValues(new Uint8Array(impl.hpke.keyLength)) // should I be getting this elsewhere?

  const { framedContent, signature } = await createContentCommitSignature(
    gc,
    "mls_public_message",
    c[0],
    { leafIndex: 1, senderType: senderTypes.member },
    new Uint8Array(),
    hexToBytes(data.signature_priv),
    impl.signature,
  )

  const authenticatedContent: AuthenticatedContent = {
    wireformat: wireformats.mls_public_message,
    content: framedContent,
    auth: { contentType: contentTypes.commit, signature: signature, confirmationTag },
  }

  const prot = await protectPublicMessage(hexToBytes(data.membership_key), gc, authenticatedContent, impl)

  const unprotected = await unprotectPublicMessage(
    hexToBytes(data.membership_key),
    gc,
    [],
    prot,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected === undefined || unprotected.content.contentType !== contentTypes.commit)
    throw new Error("could not unprotect mls public message")

  expect(encodeCommit(unprotected.content.commit)).toStrictEqual(hexToBytes(data.commit))
}

async function publicProposal(data: MessageProtectionData, gc: GroupContext, impl: CiphersuiteImpl) {
  const prop = decodeMlsMessage(hexToBytes(data.proposal_pub), 0)
  if (prop === undefined || prop[0].wireformat !== wireformats.mls_public_message)
    throw new Error("could not decode mls public message")

  const unprotected = await unprotectPublicMessage(
    hexToBytes(data.membership_key),
    gc,
    [],
    prop[0].publicMessage,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected.content.contentType !== contentTypes.proposal) throw new Error("Could not decode as proposal")

  expect(encodeProposal(unprotected.content.proposal)).toStrictEqual(hexToBytes(data.proposal))
}

async function publicCommit(data: MessageProtectionData, gc: GroupContext, impl: CiphersuiteImpl) {
  const c = decodeMlsMessage(hexToBytes(data.commit_pub), 0)
  if (c === undefined || c[0].wireformat !== wireformats.mls_public_message)
    throw new Error("could not decode mls public message")

  const unprotected = await unprotectPublicMessage(
    hexToBytes(data.membership_key),
    gc,
    [],
    c[0].publicMessage,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected.content.contentType !== contentTypes.commit) throw new Error("Could not decode as commit")

  expect(encodeCommit(unprotected.content.commit)).toStrictEqual(hexToBytes(data.commit))
}

async function publicApplicationFails(data: MessageProtectionData, gc: GroupContext, impl: CiphersuiteImpl) {
  const privateApplication = decodeMlsMessage(hexToBytes(data.application_priv), 0)
  if (privateApplication === undefined || privateApplication[0].wireformat !== wireformats.mls_private_message)
    throw new Error("could not decode mls private message")

  const secretTree = await createSecretTree(2, hexToBytes(data.encryption_secret), impl.kdf)

  const unprotected = await unprotectPrivateMessage(
    hexToBytes(data.sender_data_secret),
    privateApplication[0].privateMessage,
    secretTree,
    treeForLeafIndex1,
    gc,
    defaultKeyRetentionConfig,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected === undefined || unprotected.content.content.contentType !== contentTypes.application)
    throw new Error("could not unprotect mls private message")

  const content: AuthenticatedContent = {
    content: {
      ...unprotected.content.content,
      contentType: contentTypes.application,
      groupId: gc.groupId,
      sender: { leafIndex: 0, senderType: senderTypes.member },
      epoch: gc.epoch,
      authenticatedData: new Uint8Array(),
    },
    auth: unprotected.content.auth,
    wireformat: wireformats.mls_public_message,
  }

  await expect(protectPublicMessage(hexToBytes(data.membership_key), gc, content, impl)).rejects.toThrow(UsageError)
}

async function commit(data: MessageProtectionData, gc: GroupContext, impl: CiphersuiteImpl) {
  const privateCommit = decodeMlsMessage(hexToBytes(data.commit_priv), 0)
  if (privateCommit === undefined || privateCommit[0].wireformat !== wireformats.mls_private_message)
    throw new Error("could not decode mls private message")

  const secretTree = await createSecretTree(2, hexToBytes(data.encryption_secret), impl.kdf)

  const unprotected = await unprotectPrivateMessage(
    hexToBytes(data.sender_data_secret),
    privateCommit[0].privateMessage,
    secretTree,
    treeForLeafIndex1,
    gc,
    defaultKeyRetentionConfig,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected === undefined || unprotected.content.content.contentType !== contentTypes.commit)
    throw new Error("could not unprotect mls private message")

  expect(encodeCommit(unprotected.content.content.commit)).toStrictEqual(hexToBytes(data.commit))
}

async function application(data: MessageProtectionData, gc: GroupContext, impl: CiphersuiteImpl) {
  const privateApplication = decodeMlsMessage(hexToBytes(data.application_priv), 0)
  if (privateApplication === undefined || privateApplication[0].wireformat !== wireformats.mls_private_message)
    throw new Error("could not decode mls private message")

  const secretTree = await createSecretTree(2, hexToBytes(data.encryption_secret), impl.kdf)

  const unprotected = await unprotectPrivateMessage(
    hexToBytes(data.sender_data_secret),
    privateApplication[0].privateMessage,
    secretTree,
    treeForLeafIndex1,
    gc,
    defaultKeyRetentionConfig,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected === undefined || unprotected.content.content.contentType !== contentTypes.application)
    throw new Error("could not unprotect mls private message")

  expect(unprotected.content.content.applicationData).toStrictEqual(hexToBytes(data.application))
}

async function protectThenUnprotectProposal(data: MessageProtectionData, gc: GroupContext, impl: CiphersuiteImpl) {
  const p = decodeProposal(hexToBytes(data.proposal), 0)
  if (p === undefined) throw new Error("could not decode proposal")

  const secretTree = await createSecretTree(2, hexToBytes(data.encryption_secret), impl.kdf)

  const pro = await protectProposal(
    hexToBytes(data.signature_priv),
    hexToBytes(data.sender_data_secret),
    p[0],
    new Uint8Array(),
    gc,
    secretTree,
    1,
    defaultPaddingConfig,
    impl,
  )

  const unprotected = await unprotectPrivateMessage(
    hexToBytes(data.sender_data_secret),
    pro.privateMessage,
    secretTree,
    treeForLeafIndex1,
    gc,
    defaultKeyRetentionConfig,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected === undefined || unprotected.content.content.contentType !== contentTypes.proposal)
    throw new Error("could not unprotect mls private message")

  expect(encodeProposal(unprotected.content.content.proposal)).toStrictEqual(hexToBytes(data.proposal))
}

async function protectThenUnprotectApplication(data: MessageProtectionData, gc: GroupContext, impl: CiphersuiteImpl) {
  const secretTree = await createSecretTree(2, hexToBytes(data.encryption_secret), impl.kdf)

  const pro = await protectApplicationData(
    hexToBytes(data.signature_priv),
    hexToBytes(data.sender_data_secret),
    hexToBytes(data.application),
    new Uint8Array(),
    gc,
    secretTree,
    1,
    defaultPaddingConfig,
    impl,
  )

  const unprotected = await unprotectPrivateMessage(
    hexToBytes(data.sender_data_secret),
    pro.privateMessage,
    secretTree,
    treeForLeafIndex1,
    gc,
    defaultKeyRetentionConfig,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected === undefined || unprotected.content.content.contentType !== contentTypes.application)
    throw new Error("could not unprotect mls private message")

  expect(unprotected.content.content.applicationData).toStrictEqual(hexToBytes(data.application))
}

async function protectThenUnprotectCommit(data: MessageProtectionData, gc: GroupContext, impl: CiphersuiteImpl) {
  const c = decodeCommit(hexToBytes(data.commit), 0)
  if (c === undefined) throw new Error("could not decode commit")

  const secretTree = await createSecretTree(2, hexToBytes(data.encryption_secret), impl.kdf)

  const confirmationTag = crypto.getRandomValues(new Uint8Array(impl.hpke.keyLength)) // should I be getting this elsewhere?

  const { framedContent, signature } = await createContentCommitSignature(
    gc,
    "mls_private_message",
    c[0],
    { leafIndex: 1, senderType: senderTypes.member },
    new Uint8Array(),
    hexToBytes(data.signature_priv),
    impl.signature,
  )

  const content = {
    ...framedContent,
    auth: {
      contentType: framedContent.contentType,
      signature,
      confirmationTag,
    },
  }

  const pro = await protect(
    hexToBytes(data.sender_data_secret),
    new Uint8Array(),
    gc,
    secretTree,
    content,
    1,
    defaultPaddingConfig,
    impl,
  )

  const unprotected = await unprotectPrivateMessage(
    hexToBytes(data.sender_data_secret),
    pro.privateMessage,
    secretTree,
    treeForLeafIndex1,
    gc,
    defaultKeyRetentionConfig,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected === undefined || unprotected.content.content.contentType !== contentTypes.commit)
    throw new Error("could not unprotect mls private message")

  expect(encodeCommit(unprotected.content.content.commit)).toStrictEqual(hexToBytes(data.commit))
}

async function proposal(data: MessageProtectionData, gc: GroupContext, impl: CiphersuiteImpl) {
  const privateProposal = decodeMlsMessage(hexToBytes(data.proposal_priv), 0)
  if (privateProposal === undefined || privateProposal[0].wireformat !== wireformats.mls_private_message)
    throw new Error("could not decode mls private message")

  const secretTree = await createSecretTree(2, hexToBytes(data.encryption_secret), impl.kdf)

  const unprotected = await unprotectPrivateMessage(
    hexToBytes(data.sender_data_secret),
    privateProposal[0].privateMessage,
    secretTree,
    [
      undefined,
      undefined,
      {
        nodeType: nodeTypes.leaf,
        leaf: {
          leafNodeSource: leafNodeSources.commit,
          hpkePublicKey: new Uint8Array(),
          signaturePublicKey: new Uint8Array(),
          capabilities: defaultCapabilities(),
          parentHash: new Uint8Array(),
          extensions: [],
          signature: new Uint8Array(),
          credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array() },
        },
      },
    ],
    gc,
    defaultKeyRetentionConfig,
    impl,
    hexToBytes(data.signature_pub),
  )

  if (unprotected === undefined || unprotected.content.content.contentType !== contentTypes.proposal)
    throw new Error("could not unprotect mls private message")

  expect(encodeProposal(unprotected.content.content.proposal)).toStrictEqual(hexToBytes(data.proposal))
}
