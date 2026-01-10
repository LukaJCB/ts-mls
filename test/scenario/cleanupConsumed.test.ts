import { createGroup, joinGroup, makePskIndex } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { createApplicationMessage } from "../../src/createMessage.js"
import { processPrivateMessage } from "../../src/processMessages.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { decodeMlsMessage, encodeMlsMessage } from "../../src/message.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { zeroOutUint8Array } from "../../src/util/byteArray.js"
import { CryptoError } from "../../src/mlsError.js"
import { PrivateMessage } from "../../src/privateMessage.js"

test.concurrent.each(Object.keys(ciphersuites).slice(0, 1))(`Cleanup consumed values %s`, async (cs) => {
  await cleanup(cs as CiphersuiteName)
})

async function cleanup(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

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

  const commitResult1 = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    {
      extraProposals: [addBobProposal],
    },
  )

  aliceGroup = commitResult1.newState

  const bobGroup = await joinGroup(
    commitResult1.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  const messageToBob = new TextEncoder().encode("Hello bob!")

  const sendMessageFn = async () => await createApplicationMessage(aliceGroup, messageToBob, impl)

  const receiveMessageFn = async (pm: PrivateMessage) =>
    await processPrivateMessage(bobGroup, pm, makePskIndex(bobGroup, {}), impl)

  //alice can create messages to bob as many times as she wants with the same ClientState
  const aliceCreateMessageResult1 = await sendMessageFn()

  const aliceCreateMessageResult2 = await sendMessageFn()

  //bob can receive the same message over and over with the same ClientState
  const bobProcessMessageResult1 = await receiveMessageFn(aliceCreateMessageResult1.privateMessage)

  const bobProcessMessageResult2 = await receiveMessageFn(aliceCreateMessageResult2.privateMessage)

  if (bobProcessMessageResult1.kind === "newState" || bobProcessMessageResult2.kind === "newState")
    throw new Error("Expected application message")

  expect(bobProcessMessageResult1.message).toStrictEqual(messageToBob)
  expect(bobProcessMessageResult1.message).toStrictEqual(bobProcessMessageResult2.message)

  //we delete the consumed ratchet for alice
  aliceCreateMessageResult1.consumed.forEach(zeroOutUint8Array)

  //alice can no longer properly encrypt this message
  const aliceCreateMessageResult3 = await sendMessageFn()

  // bob cannot decrypt alice's broken message
  await expect(receiveMessageFn(aliceCreateMessageResult3.privateMessage)).rejects.toThrow(CryptoError)

  //bob can still decrypt alice's old message
  const bobProcessMessageResult3 = await receiveMessageFn(aliceCreateMessageResult2.privateMessage)
  if (bobProcessMessageResult3.kind === "newState") throw new Error("Expected application message")
  expect(bobProcessMessageResult3.message).toStrictEqual(bobProcessMessageResult1.message)

  //we delete the consumed ratchet for bob
  bobProcessMessageResult3.consumed.forEach(zeroOutUint8Array)

  //bob can no longer decrypt the message
  await expect(receiveMessageFn(aliceCreateMessageResult1.privateMessage)).rejects.toThrow(CryptoError)

  await checkHpkeKeysMatch(bobProcessMessageResult3.newState, impl)
  await checkHpkeKeysMatch(aliceCreateMessageResult2.newState, impl)
}
