import { Capabilities } from "../../src/capabilities"
import {
  createApplicationMessage,
  createCommit,
  createGroup,
  joinGroup,
  processPrivateMessage,
} from "../../src/clientState"
import { Credential } from "../../src/credential"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { Lifetime } from "../../src/lifetime"
import { decodeMlsMessage, encodeMlsMessage } from "../../src/message"
import { ProposalAdd } from "../../src/proposal"

const defaultCapabilities: Capabilities = {
  versions: ["mls10"],
  ciphersuites: Object.keys(ciphersuites) as CiphersuiteName[],
  extensions: ["ratchet_tree"],
  proposals: [],
  credentials: ["basic", "x509"],
}

const defaultLifetime: Lifetime = {
  notBefore: 0n,
  notAfter: 9223372036854775807n,
}

test("1:1 join MLS_128_DHKEMP256_AES128GCM_SHA256_P256", async () => {
  await oneToOne("MLS_128_DHKEMP256_AES128GCM_SHA256_P256")
})

test("1:1 join MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", async () => {
  await oneToOne("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
})

test("1:1 join MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519", async () => {
  await oneToOne("MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519")
})

test("1:1 join MLS_256_XWING_AES256GCM_SHA512_Ed25519", async () => {
  await oneToOne("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
})

test("1:1 join MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519", async () => {
  await oneToOne("MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519")
})

async function oneToOne(cipherSuite: CiphersuiteName) {
  const impl = getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

  // bob sends keyPackage to alice
  const keyPackageMessage = encodeMlsMessage({
    keyPackage: bob.publicPackage,
    wireformat: "mls_key_package",
    version: "mls10",
  })

  // alice decodes bob's keyPackage
  const decodedKeyPackage = decodeMlsMessage(keyPackageMessage, 0)![0]

  if (decodedKeyPackage.wireformat !== "mls_key_package") throw new Error("Expected key package")

  // alice creates proposal to add bob
  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: decodedKeyPackage.keyPackage,
    },
  }

  // alice commits
  const commitResult = await createCommit(aliceGroup, {}, false, [addBobProposal], impl)

  aliceGroup = commitResult.newState

  // alice sends welcome message to bob
  const encodedWelcome = encodeMlsMessage({
    welcome: commitResult.welcome!,
    wireformat: "mls_welcome",
    version: "mls10",
  })

  // bob decodes the welcome message
  const decodedWelcome = decodeMlsMessage(encodedWelcome, 0)![0]

  if (decodedWelcome.wireformat !== "mls_welcome") throw new Error("Expected welcome")

  // bob creates his own group state
  let bobGroup = await joinGroup(
    decodedWelcome.welcome,
    bob.publicPackage,
    bob.privatePackage,
    [],
    impl,
    aliceGroup.ratchetTree,
  )

  // ensure epochAuthenticator values are equal
  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const messageToBob = new TextEncoder().encode("Hello bob!")

  // alice creates a message to the group
  const aliceCreateMessageResult = await createApplicationMessage(aliceGroup, messageToBob, impl)

  aliceGroup = aliceCreateMessageResult.newState

  // alice sends the message to bob
  const encodedPrivateMessageAlice = encodeMlsMessage({
    privateMessage: aliceCreateMessageResult.privateMessage,
    wireformat: "mls_private_message",
    version: "mls10",
  })

  // bob decodes the message
  const decodedPrivateMessageAlice = decodeMlsMessage(encodedPrivateMessageAlice, 0)![0]

  if (decodedPrivateMessageAlice.wireformat !== "mls_private_message") throw new Error("Expected private message")

  // bob receives the message
  const bobProcessMessageResult = await processPrivateMessage(
    bobGroup,
    decodedPrivateMessageAlice.privateMessage,
    {},
    impl,
  )

  bobGroup = bobProcessMessageResult.newState

  if (bobProcessMessageResult.kind === "newState") throw new Error("Expected application message")

  expect(bobProcessMessageResult.message).toStrictEqual(messageToBob)

  const messageToAlice = new TextEncoder().encode("Hello alice!")

  const bobCreateMessageResult = await createApplicationMessage(bobGroup, messageToAlice, impl)

  bobGroup = bobCreateMessageResult.newState

  const encodedPrivateMessageBob = encodeMlsMessage({
    privateMessage: bobCreateMessageResult.privateMessage,
    wireformat: "mls_private_message",
    version: "mls10",
  })

  const decodedPrivateMessageBob = decodeMlsMessage(encodedPrivateMessageBob, 0)![0]

  if (decodedPrivateMessageBob.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const aliceProcessMessageResult = await processPrivateMessage(
    aliceGroup,
    decodedPrivateMessageBob.privateMessage,
    {},
    impl,
  )

  aliceGroup = aliceProcessMessageResult.newState

  if (aliceProcessMessageResult.kind === "newState") throw new Error("Expected application message")

  expect(aliceProcessMessageResult.message).toStrictEqual(messageToAlice)
}
