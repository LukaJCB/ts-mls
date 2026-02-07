import { createGroup, joinGroup } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteImpl, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"

import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { CryptoProvider, defaultCryptoProvider, Kdf } from "../../src/index.js"
import { testEveryoneCanMessageEveryone } from "./common.js"
import { extract, expand } from "@noble/hashes/hkdf.js"
import { sha256 } from "@noble/hashes/sha2.js"

describe("Custom crypto provider", () => {
  test("create custom implementation", async () => {
    const customSha256Hkdf: Kdf = {
      async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
        return extract(sha256, ikm, salt)
      },
      async expand(prk: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> {
        return expand(sha256, prk, info, len)
      },
      size: 32,
    }

    const customProvider: CryptoProvider = {
      async getCiphersuiteImpl(id: number): Promise<CiphersuiteImpl> {
        const defaultImpl = await defaultCryptoProvider.getCiphersuiteImpl(id)
        if (id === ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) {
          return { ...defaultImpl, kdf: customSha256Hkdf }
        } else {
          return defaultImpl
        }
      },
    }

    // we will create a CiphersuiteImpl with the new provider
    const impl: CiphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      customProvider,
    )

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

    const charlieCredential: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("charlie"),
    }
    const charlie = await generateKeyPackage({
      credential: charlieCredential,
      cipherSuite: impl,
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
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: aliceGroup,
      extraProposals: [addBobProposal, addCharlieProposal],
      ratchetTreeExtension: true,
    })

    aliceGroup = addBobAndCharlieCommitResult.newState

    const bobGroup = await joinGroup({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      welcome: addBobAndCharlieCommitResult.welcome!.welcome,
      keyPackage: bob.publicPackage,
      privateKeys: bob.privatePackage,
    })

    expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

    const charlieGroup = await joinGroup({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      welcome: addBobAndCharlieCommitResult.welcome!.welcome,
      keyPackage: charlie.publicPackage,
      privateKeys: charlie.privatePackage,
    })

    expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

    await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
  })
})
