import { createGroup, joinGroup, ClientState, makePskIndex } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { processPrivateMessage } from "../../src/processMessages"
import { emptyPskIndex } from "../../src/pskIndex"
import { getCiphersuiteFromName, CiphersuiteName, ciphersuites, CiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { generateKeyPackage, KeyPackage, PrivateKeyPackage } from "../../src/keyPackage"
import { Credential } from "../../src/credential"
import { ProposalAdd, ProposalRemove } from "../../src/proposal"
import { shuffledIndices, testEveryoneCanMessageEveryone } from "./common"
import { defaultLifetime } from "../../src/lifetime"
import { defaultCapabilities } from "../../src/defaultCapabilities"

import { randomInt } from "crypto"

for (const cs of Object.keys(ciphersuites)) {
  test(`Large Group, Full Lifecycle ${cs}`, async () => {
    await largeGroupFullLifecycle(cs as CiphersuiteName, 5, 8)
  }, 60000)
}

type MemberState = { id: string; state: ClientState; public: KeyPackage; private: PrivateKeyPackage }

async function largeGroupFullLifecycle(cipherSuite: CiphersuiteName, initialSize: number, targetSize: number) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))
  const groupId = new TextEncoder().encode("dynamic-group")

  const makeCredential = (name: string): Credential => ({
    credentialType: "basic",
    identity: new TextEncoder().encode(name),
  })

  const memberStates: MemberState[] = []

  const initialCreatorName = "member-0"
  const creatorCred = makeCredential(initialCreatorName)
  const creatorKP = await generateKeyPackage(creatorCred, defaultCapabilities(), defaultLifetime, [], impl)
  const creatorGroup = await createGroup(groupId, creatorKP.publicPackage, creatorKP.privatePackage, [], impl)

  memberStates.push({
    id: initialCreatorName,
    state: creatorGroup,
    public: creatorKP.publicPackage,
    private: creatorKP.privatePackage,
  })

  // Add first M members
  for (let i = 1; i < initialSize; i++) {
    await addMember(memberStates, i, impl)
  }

  for (const index of shuffledIndices(memberStates)) {
    await update(memberStates, index, impl)
  }

  // Until group size is N
  for (let i = memberStates.length; i < targetSize; i++) {
    const adderIndex = randomInt(memberStates.length)
    await addMember(memberStates, i, impl, adderIndex)
  }

  await testEveryoneCanMessageEveryone(
    memberStates.map((ms) => ms.state),
    impl,
  )

  const shuffled = shuffledIndices(memberStates)
  for (const index of shuffled) {
    await update(memberStates, index, impl)
  }

  await testEveryoneCanMessageEveryone(
    memberStates.map((ms) => ms.state),
    impl,
  )

  // While group size > 1, randomly remove someone
  while (memberStates.length > 1) {
    const removerIndex = randomInt(memberStates.length)
    let removedIndex = randomInt(memberStates.length)
    while (removedIndex === removerIndex) {
      removedIndex = randomInt(memberStates.length)
    }

    const remover = memberStates[removerIndex]!
    const removed = memberStates[removedIndex]!

    const removeProposal: ProposalRemove = {
      proposalType: "remove",
      remove: {
        removed: removed.state.privatePath.leafIndex,
      },
    }

    const commitResult = await createCommit(remover.state, emptyPskIndex, false, [removeProposal], impl)

    if (commitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")
    remover.state = commitResult.newState

    // Apply the commit to all members (except removed and remover)
    for (let i = 0; i < memberStates.length; i++) {
      if (i === removerIndex) continue
      const m = memberStates[i]!
      const result = await processPrivateMessage(
        m.state,
        commitResult.commit.privateMessage,
        makePskIndex(m.state, {}),
        impl,
      )
      m.state = result.newState
    }

    // Remove the member from the group
    memberStates.splice(removedIndex, 1)

    await testEveryoneCanMessageEveryone(
      memberStates.map((ms) => ms.state),
      impl,
    )
  }
}

async function addMember(memberStates: MemberState[], index: number, impl: CiphersuiteImpl, adderIndex = 0) {
  const newName = `member-${index}`
  const newCred = {
    credentialType: "basic" as const,
    identity: new TextEncoder().encode(newName),
  }
  const newKP = await generateKeyPackage(newCred, defaultCapabilities(), defaultLifetime, [], impl)

  const adder = memberStates[adderIndex]!

  const addProposal: ProposalAdd = {
    proposalType: "add" as const,
    add: { keyPackage: newKP.publicPackage },
  }

  const commitResult = await createCommit(adder.state, emptyPskIndex, false, [addProposal], impl)

  if (commitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  adder.state = commitResult.newState

  const newState = await joinGroup(
    commitResult.welcome!,
    newKP.publicPackage,
    newKP.privatePackage,
    emptyPskIndex,
    impl,
    adder.state.ratchetTree,
  )

  // Update all existing members (excluding adder)
  for (let i = 0; i < memberStates.length; i++) {
    if (i === adderIndex) continue
    const m = memberStates[i]!
    const result = await processPrivateMessage(
      m.state,
      commitResult.commit.privateMessage,
      makePskIndex(m.state, {}),
      impl,
    )

    m.state = result.newState
  }

  // Add new member
  memberStates.push({ id: newName, state: newState, public: newKP.publicPackage, private: newKP.privatePackage })
}

async function update(memberStates: MemberState[], updateIndex: number, impl: CiphersuiteImpl) {
  const updater = memberStates[updateIndex]!

  const emptyCommitResult = await createCommit(updater.state, emptyPskIndex, false, [], impl)

  updater.state = emptyCommitResult.newState

  if (emptyCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  // Update all existing members (including adder)
  for (let i = 0; i < memberStates.length; i++) {
    if (i === updateIndex) continue
    const m = memberStates[i]!
    const result = await processPrivateMessage(
      m.state,
      emptyCommitResult.commit.privateMessage,
      makePskIndex(m.state, {}),
      impl,
    )

    m.state = result.newState
  }
}
