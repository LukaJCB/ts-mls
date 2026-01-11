import { createGroup, joinGroup, makePskIndex } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { processPrivateMessage } from "../../src/processMessages.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/credentialType.js"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { Proposal, ProposalAdd } from "../../src/proposal.js"
import { bytesToBase64 } from "../../src/util/byteArray.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import { testEveryoneCanMessageEveryone } from "./common.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"

test.concurrent.each(Object.keys(ciphersuites))(`External PSK %s`, async (cs) => {
  await externalPsk(cs as CiphersuiteName)
})

async function externalPsk(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("bob"),
  }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const commitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    {
      extraProposals: [addBobProposal],
    },
  )

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
    proposalType: defaultProposalTypes.psk,
    psk: {
      preSharedKeyId: {
        psktype: "external",
        pskId: pskId1,
        pskNonce: pskNonce1,
      },
    },
  }

  const pskProposal2: Proposal = {
    proposalType: defaultProposalTypes.psk,
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
    {
      state: aliceGroup,
      pskIndex: makePskIndex(aliceGroup, sharedPsks),
      cipherSuite: impl,
    },
    {
      extraProposals: [pskProposal1, pskProposal2],
    },
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
