import { createGroup, joinGroup, makePskIndex } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { processPrivateMessage } from "../../src/processMessages"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { Proposal, ProposalAdd } from "../../src/proposal"
import { bytesToBase64 } from "../../src/util/byteArray"
import { checkHpkeKeysMatch } from "../crypto/keyMatch"
import { defaultCapabilities, defaultLifetime, testEveryoneCanMessageEveryone } from "./common"

for (const cs of Object.keys(ciphersuites)) {
  test(`External PSK ${cs}`, async () => {
    await externalPsk(cs as CiphersuiteName)
  })
}

async function externalPsk(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

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

  const pskSecret = impl.rng.randomBytes(impl.kdf.size)
  const pskNonce = impl.rng.randomBytes(impl.kdf.size)

  const pskId = new TextEncoder().encode("psk-1")

  const pskProposal: Proposal = {
    proposalType: "psk",
    psk: {
      preSharedKeyId: {
        psktype: "external",
        pskId,
        pskNonce,
      },
    },
  }

  const base64PskId = bytesToBase64(pskId)

  const sharedPsks = { [base64PskId]: pskSecret }

  const pskCommitResult = await createCommit(
    aliceGroup,
    makePskIndex(aliceGroup, sharedPsks),
    false,
    [pskProposal],
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
