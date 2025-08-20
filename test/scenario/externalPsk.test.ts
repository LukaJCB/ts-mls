import { createGroup, joinGroup, makePskIndex } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { processPrivateMessage } from "../../src/processMessages"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { generateKeyPackage } from "../../src/keyPackage"
import { Proposal, ProposalAdd } from "../../src/proposal"
import { bytesToBase64 } from "../../src/util/byteArray"
import { checkHpkeKeysMatch } from "../crypto/keyMatch"
import { testEveryoneCanMessageEveryone } from "./common"
import { defaultLifetime } from "../../src/lifetime"
import { defaultCapabilities } from "../../src/defaultCapabilities"

for (const cs of Object.keys(ciphersuites)) {
  test(`External PSK ${cs}`, async () => {
    await externalPsk(cs as CiphersuiteName)
  })
}

async function externalPsk(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const commitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)

  aliceGroup = commitResult.newState

  let bobGroup = await joinGroup(
    commitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  const pskSecret1 = impl.rng.randomBytes(impl.kdf.size)
  const pskSecret2 = impl.rng.randomBytes(impl.kdf.size)
  const pskNonce1 = impl.rng.randomBytes(impl.kdf.size)
  const pskNonce2 = impl.rng.randomBytes(impl.kdf.size)

  const pskId1 = new TextEncoder().encode("psk-1")
  const pskId2 = new TextEncoder().encode("psk-1")

  const pskProposal1: Proposal = {
    proposalType: "psk",
    psk: {
      preSharedKeyId: {
        psktype: "external",
        pskId: pskId1,
        pskNonce: pskNonce1,
      },
    },
  }

  const pskProposal2: Proposal = {
    proposalType: "psk",
    psk: {
      preSharedKeyId: {
        psktype: "external",
        pskId: pskId2,
        pskNonce: pskNonce2,
      },
    },
  }

  const base64PskId1 = bytesToBase64(pskId1)

  const base64PskId2 = bytesToBase64(pskId2)

  const sharedPsks = { [base64PskId1]: pskSecret1, [base64PskId2]: pskSecret2 }

  const pskCommitResult = await createCommit(
    aliceGroup,
    makePskIndex(aliceGroup, sharedPsks),
    false,
    [pskProposal1, pskProposal2],
    impl,
  )

  aliceGroup = pskCommitResult.newState

  if (pskCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const processPskResult = await processPrivateMessage(
    bobGroup,
    pskCommitResult.commit.privateMessage,
    makePskIndex(bobGroup, sharedPsks),
    impl,
  )

  bobGroup = processPskResult.newState

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
}
