import { createGroup, joinGroup } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { generateKeyPackage } from "../../src/keyPackage"
import { ProposalAdd } from "../../src/proposal"
import { defaultLifetime } from "../../src/lifetime"
import { defaultCapabilities } from "../../src/defaultCapabilities"
import { Capabilities } from "../../src/capabilities"
import { Extension, ExtensionType } from "../../src/extension"
import { ValidationError } from "../../src/mlsError"

test.each(Object.keys(ciphersuites))(`Custom Extensions %s`, async (cs) => {
  await customExtensionTest(cs as CiphersuiteName)
})

async function customExtensionTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const customExtensionType: ExtensionType = 7

  const capabilities: Capabilities = {
    extensions: [customExtensionType],
    credentials: ["basic"],
    proposals: [],
    versions: ["mls10"],
    ciphersuites: [cipherSuite],
  }

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, capabilities, defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  const extensionData = new TextEncoder().encode("custom extension data")

  const customExtension: Extension = {
    extensionType: customExtensionType,
    extensionData: extensionData,
  }

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [customExtension], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, capabilities, defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit(
    {
      state: aliceGroup,
      cipherSuite: impl,
    },
    {
      extraProposals: [addBobProposal],
    },
  )

  aliceGroup = addBobCommitResult.newState

  const bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  expect(bobGroup.groupContext.extensions.find((e) => e.extensionType === customExtensionType)).toStrictEqual(
    customExtension,
  )

  //Charlie doesn't support the custom extension
  const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addCharlieProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: charlie.publicPackage,
    },
  }

  await expect(
    createCommit(
      {
        state: aliceGroup,
        cipherSuite: impl,
      },
      { extraProposals: [addCharlieProposal] },
    ),
  ).rejects.toThrow(ValidationError)
}
