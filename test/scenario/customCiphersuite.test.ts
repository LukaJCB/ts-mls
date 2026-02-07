import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteImpl } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"

import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { Hash } from "../../src/index.js"
import { blake3 } from "@noble/hashes/blake3.js"
import { constantTimeEqual } from "../../src/util/constantTimeCompare.js"
import { testEveryoneCanMessageEveryone } from "./common.js"

describe("Custom ciphersuites", () => {
  test("create simple custom ciphersuite", async () => {
    const ciphersuiteId = 141

    const defaultImpl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")

    const blake3Hash: Hash = {
      async digest(data: Uint8Array) {
        return blake3(data)
      },
      async mac(key: Uint8Array, data: Uint8Array) {
        return blake3(data, { key })
      },
      async verifyMac(key: Uint8Array, mac: Uint8Array, data: Uint8Array) {
        const computedMac = blake3(data, { key })
        return constantTimeEqual(computedMac, mac)
      },
    }

    // we will create a new ciphersuite "MLS_128_DHKEMX25519_AES128GCM_BLAKE3_Ed25519"
    const customCiphersuiteImpl: CiphersuiteImpl = {
      hash: blake3Hash,
      hpke: defaultImpl.hpke,
      signature: defaultImpl.signature,
      kdf: defaultImpl.kdf,
      rng: defaultImpl.rng,
      id: ciphersuiteId,
    }

    const aliceCredential: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("alice"),
    }
    const alice = await generateKeyPackage({
      credential: aliceCredential,
      cipherSuite: customCiphersuiteImpl,
    })

    const groupId = new TextEncoder().encode("group1")

    let aliceGroup = await createGroup({
      context: { cipherSuite: customCiphersuiteImpl, authService: unsafeTestingAuthenticationService },
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
      cipherSuite: customCiphersuiteImpl,
    })

    const charlieCredential: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("charlie"),
    }
    const charlie = await generateKeyPackage({
      credential: charlieCredential,
      cipherSuite: customCiphersuiteImpl,
    })

    const addBobProposal: ProposalAdd = {
      proposalType: defaultProposalTypes.add,
      add: {
        keyPackage: bob.publicPackage,
      },
    }

    const addCharlieProposal: ProposalAdd = {
      proposalType: defaultProposalTypes.add,
      add: {
        keyPackage: charlie.publicPackage,
      },
    }

    const addBobAndCharlieCommitResult = await createCommit({
      context: {
        cipherSuite: customCiphersuiteImpl,
        authService: unsafeTestingAuthenticationService,
      },
      state: aliceGroup,
      extraProposals: [addBobProposal, addCharlieProposal],
      ratchetTreeExtension: true,
    })

    aliceGroup = addBobAndCharlieCommitResult.newState

    const bobGroup = await joinGroup({
      context: {
        cipherSuite: customCiphersuiteImpl,
        authService: unsafeTestingAuthenticationService,
      },
      welcome: addBobAndCharlieCommitResult.welcome!.welcome,
      keyPackage: bob.publicPackage,
      privateKeys: bob.privatePackage,
    })

    expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

    const charlieGroup = await joinGroup({
      context: {
        cipherSuite: customCiphersuiteImpl,
        authService: unsafeTestingAuthenticationService,
      },
      welcome: addBobAndCharlieCommitResult.welcome!.welcome,
      keyPackage: charlie.publicPackage,
      privateKeys: charlie.privatePackage,
    })

    expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

    await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], customCiphersuiteImpl)
  })
})
