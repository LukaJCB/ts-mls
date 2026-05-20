import { createGroup, joinGroup, getOwnLeafNode } from "../../src/clientState.js"
import { createUpdateProposal } from "../../src/createMessage.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { ciphersuites, CiphersuiteName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { updateLeafKey } from "../../src/privateKeyPath.js"
import { fastEqual } from "../../src/util/byteArray.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"
import { acceptAll } from "../../src/incomingMessageAction.js"
import {
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"

test.concurrent.each(Object.keys(ciphersuites))(
  `Receiver of own update installed before processing decrypts path %s`,
  async (cs) => {
    const impl = await getCiphersuiteImpl(cs as CiphersuiteName)

    const aliceCred: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("alice"),
    }
    const alice = await generateKeyPackage({ credential: aliceCred, cipherSuite: impl })
    let aliceGroup = await createGroup({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      groupId: new TextEncoder().encode("group1"),
      keyPackage: alice.publicPackage,
      privateKeyPackage: alice.privatePackage,
    })

    const bobCred: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("bob"),
    }
    const bob = await generateKeyPackage({ credential: bobCred, cipherSuite: impl })
    const addBob: ProposalAdd = {
      proposalType: defaultProposalTypes.add,
      add: { keyPackage: bob.publicPackage },
    }
    const addBobCommit = await createCommitEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      extraProposals: [addBob],
      ratchetTreeExtension: true,
    })
    aliceGroup = addBobCommit.newState
    let bobGroup = await joinGroup({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      welcome: addBobCommit.welcome!.welcome,
      keyPackage: bob.publicPackage,
      privateKeys: bob.privatePackage,
    })

    const bobUpdate = await createUpdateProposal({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: bobGroup,
      wireAsPublicMessage: false,
    })
    bobGroup = bobUpdate.newState

    const aliceProcess = await processMessageEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      message: bobUpdate.message,
      callback: acceptAll,
    })
    aliceGroup = aliceProcess.newState

    const aliceCommit = await createCommitEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      ratchetTreeExtension: false,
    })
    aliceGroup = aliceCommit.newState

    bobGroup = {
      ...bobGroup,
      privatePath: updateLeafKey(bobGroup.privatePath, bobUpdate.newLeafKeypair.hpkePrivateKey),
    }

    const bobProcess = await processMessageEnsureNoMutation({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: bobGroup,
      message: aliceCommit.commit,
      callback: acceptAll,
    })
    bobGroup = bobProcess.newState

    expect(fastEqual(getOwnLeafNode(bobGroup).hpkePublicKey, bobUpdate.newLeafKeypair.hpkePublicKey)).toBe(true)
    expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
    await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
  },
)
