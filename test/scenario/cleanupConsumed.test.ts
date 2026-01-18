import { createGroup, joinGroup, makePskIndex } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { createApplicationMessage } from "../../src/createMessage.js"
import { processMessage } from "../../src/processMessages.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { mlsMessageDecoder, mlsMessageEncoder, MlsFramedMessage } from "../../src/message.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { ProposalAdd } from "../../src/proposal.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"

import { zeroOutUint8Array } from "../../src/util/byteArray.js"
import { CryptoError } from "../../src/mlsError.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`Cleanup consumed values %s`, async (cs) => {
  await cleanup(cs as CiphersuiteName)
})

async function cleanup(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({
    credential: aliceCredential,
    cipherSuite: impl,
  })

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage({
    credential: bobCredential,
    cipherSuite: impl,
  })

  // bob sends keyPackage to alice
  const keyPackageMessage = encode(mlsMessageEncoder, {
    keyPackage: bob.publicPackage,
    wireformat: wireformats.mls_key_package,
    version: protocolVersions.mls10,
  })

  // alice decodes bob's keyPackage
  const decodedKeyPackage = mlsMessageDecoder(keyPackageMessage, 0)![0]

  if (decodedKeyPackage.wireformat !== wireformats.mls_key_package) throw new Error("Expected key package")

  // alice creates proposal to add bob
  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: decodedKeyPackage.keyPackage,
    },
  }

  const commitResult1 = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
    extraProposals: [addBobProposal],
  })

  aliceGroup = commitResult1.newState

  const bobGroup = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: commitResult1.welcome!,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: aliceGroup.ratchetTree,
  })

  const messageToBob = new TextEncoder().encode("Hello bob!")

  const sendMessageFn = async () =>
    await createApplicationMessage({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      message: messageToBob,
    })

  const receiveMessageFn = async (message: MlsFramedMessage) =>
    await processMessage({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        pskIndex: makePskIndex(bobGroup, {}),
      },
      state: bobGroup,
      message,
    })

  //alice can create messages to bob as many times as she wants with the same ClientState
  const aliceCreateMessageResult1 = await sendMessageFn()

  const aliceCreateMessageResult2 = await sendMessageFn()

  //bob can receive the same message over and over with the same ClientState
  const bobProcessMessageResult1 = await receiveMessageFn(aliceCreateMessageResult1.message)

  const bobProcessMessageResult2 = await receiveMessageFn(aliceCreateMessageResult2.message)

  if (bobProcessMessageResult1.kind === "newState" || bobProcessMessageResult2.kind === "newState")
    throw new Error("Expected application message")

  expect(bobProcessMessageResult1.message).toStrictEqual(messageToBob)
  expect(bobProcessMessageResult1.message).toStrictEqual(bobProcessMessageResult2.message)

  //we delete the consumed ratchet for alice
  aliceCreateMessageResult1.consumed.forEach(zeroOutUint8Array)

  //alice can no longer properly encrypt this message
  const aliceCreateMessageResult3 = await sendMessageFn()

  // bob cannot decrypt alice's broken message
  await expect(receiveMessageFn(aliceCreateMessageResult3.message)).rejects.toThrow(CryptoError)

  //bob can still decrypt alice's old message
  const bobProcessMessageResult3 = await receiveMessageFn(aliceCreateMessageResult2.message)
  if (bobProcessMessageResult3.kind === "newState") throw new Error("Expected application message")
  expect(bobProcessMessageResult3.message).toStrictEqual(bobProcessMessageResult1.message)

  //we delete the consumed ratchet for bob
  bobProcessMessageResult3.consumed.forEach(zeroOutUint8Array)

  //bob can no longer decrypt the message
  await expect(receiveMessageFn(aliceCreateMessageResult1.message)).rejects.toThrow(CryptoError)

  await checkHpkeKeysMatch(bobProcessMessageResult3.newState, impl)
  await checkHpkeKeysMatch(aliceCreateMessageResult2.newState, impl)
}
