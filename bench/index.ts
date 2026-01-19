import { Bench } from "tinybench"
import fs from "fs"
import {
  Credential,
  defaultCredentialTypes,
  defaultProposalTypes,
  generateKeyPackage,
  CiphersuiteImpl,
  CiphersuiteName,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  createGroup,
  Proposal,
  createCommit,
  emptyPskIndex,
  KeyPackage,
  PrivateKeyPackage,
  CreateCommitResult,
  joinGroup,
  ClientState,
  processPrivateMessage,
  createApplicationMessage,
  processMessage,
  acceptAll,
  unsafeTestingAuthenticationService,
} from "../src/index.js"
import { MlsPrivateMessage } from "../src/message.js"

function parseTable(row: Record<string, string | number | undefined> | null): {
  name: string
  avg: number
  med: number
  latencyAvg: number
  latencyMed: number
  samples: unknown
} {
  return {
    name: row!["Task name"]! as string,
    avg: parseFloat(row!["Throughput avg (ops/s)"] as string),
    med: parseFloat(row!["Throughput med (ops/s)"] as string),
    latencyAvg: parseFloat(row!["Latency avg (ns)"] as string),
    latencyMed: parseFloat(row!["Latency med (ns)"] as string),
    samples: row!["Samples"],
  }
}

async function createKeyPackageBench(impl: CiphersuiteImpl) {
  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new Uint8Array([0, 1, 2]),
  }
  return await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })
}

async function createGroupBench(impl: CiphersuiteImpl) {
  const res = await initGroup(impl)

  await addMember(impl, res.result)
}

async function joinGroupBench(
  impl: CiphersuiteImpl,
  pkp: PrivateKeyPackage,
  kp: KeyPackage,
  result: CreateCommitResult,
) {
  await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: result.welcome!.welcome,
    keyPackage: kp,
    privateKeys: pkp,
    ratchetTree: result.newState.ratchetTree,
  })
}

async function createCommitBench(impl: CiphersuiteImpl, aliceGroup: ClientState) {
  await createCommit({
    context: {
      pskIndex: emptyPskIndex,
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: aliceGroup,
  })
}

async function processCommitBench(impl: CiphersuiteImpl, bobGroup: ClientState, result: CreateCommitResult) {
  await processPrivateMessage({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
      pskIndex: emptyPskIndex,
    },
    state: bobGroup,
    privateMessage: (result.commit as MlsPrivateMessage).privateMessage,
  })
}

async function initGroup(impl: CiphersuiteImpl) {
  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new Uint8Array([0, 1, 2]),
  }
  const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })

  const groupId = new Uint8Array([0, 1, 2])

  const result = await createGroup({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  return { alice, result }
}

async function removeMember(impl: CiphersuiteImpl, state: ClientState) {
  const removeBobProposal: Proposal = {
    proposalType: defaultProposalTypes.remove,
    remove: {
      removed: 1,
    },
  }

  const result = await createCommit({
    context: {
      pskIndex: emptyPskIndex,
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state,
    extraProposals: [removeBobProposal],
  })

  return result
}

async function addMember(impl: CiphersuiteImpl, state: ClientState) {
  const bobCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new Uint8Array([0, 1, 3]),
  }
  const bob = await generateKeyPackage({ credential: bobCredential, cipherSuite: impl })

  const addBobProposal: Proposal = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const result = await createCommit({
    context: {
      pskIndex: emptyPskIndex,
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state,
    extraProposals: [addBobProposal],
  })

  return { bob, result }
}

async function generateKeyPackages(impl: CiphersuiteImpl, members: number): Promise<KeyPackage[]> {
  const kps: KeyPackage[] = []
  for (let i = 0; i < members; i++) {
    const cred: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode(i.toString()),
    }

    const member = await generateKeyPackage({ credential: cred, cipherSuite: impl })
    kps.push(member.publicPackage)
  }

  return kps
}

async function addMembers(impl: CiphersuiteImpl, initialState: ClientState, kps: KeyPackage[]) {
  const chunkSize = 100
  let state = initialState
  for (let i = 0; i < kps.length; i += chunkSize) {
    const chunkEnd = Math.min(i + chunkSize, kps.length)
    const proposals: Proposal[] = []

    for (let x = i; x < chunkEnd; x++) {
      const member = kps[x]!

      proposals.push({
        proposalType: defaultProposalTypes.add,
        add: {
          keyPackage: member,
        },
      })
    }

    const result = await createCommit({
      context: {
        pskIndex: emptyPskIndex,
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state,
      extraProposals: proposals,
    })

    state = result.newState
  }

  return state
}

async function runBenchmark(outputPath: string, bench: Bench) {
  await bench.run()
  console.log(bench.name)
  console.table(bench.table())

  const results = bench.table().map(parseTable)

  fs.mkdirSync("results", { recursive: true })
  fs.writeFileSync(outputPath, JSON.stringify(results, null, 2))
}

async function runBenchBasic(outputPath: string, cs: CiphersuiteName) {
  const bench = new Bench({ name: `basic ${cs}`, iterations: 1000 })
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cs))

  bench
    .add("Generate KeyPackage", async () => await createKeyPackageBench(impl))
    .add("Create group & welcome", async () => await createGroupBench(impl))

  await runBenchmark(outputPath, bench)
}

async function runBench(outputPath: string, cs: CiphersuiteName, groupSize: number) {
  const bench = new Bench({ name: `${cs}, ${groupSize} members`, iterations: 10 })

  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cs))

  const createResult = await initGroup(impl)
  const kps = await generateKeyPackages(impl, groupSize - 1)
  const addMembersResult = await addMembers(impl, createResult.result, kps)
  const initResult = await addMember(impl, addMembersResult)

  const joinResult = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: initResult.result.welcome!.welcome,
    keyPackage: initResult.bob.publicPackage,
    privateKeys: initResult.bob.privatePackage,
    ratchetTree: initResult.result.newState.ratchetTree,
  })

  const commitResult = await createCommit({
    context: {
      pskIndex: emptyPskIndex,
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: initResult.result.newState,
  })

  const sendMessageResult = await createApplicationMessage({
    context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
    state: initResult.result.newState,
    message: new Uint8Array([1, 2, 3, 4, 5]),
  })
  const addMemberResult = await addMember(impl, initResult.result.newState)

  const removeMemberResult = await removeMember(impl, initResult.result.newState)

  bench
    .add(`Add ${groupSize - 1} group members`, async () => await addMembers(impl, createResult.result, kps))
    .add(
      "Join group",
      async () =>
        await joinGroupBench(impl, initResult.bob.privatePackage, initResult.bob.publicPackage, initResult.result),
    )
    .add("Create empty commit", async () => await createCommitBench(impl, initResult.result.newState))
    .add("Process empty commit", async () => await processCommitBench(impl, joinResult, commitResult))
    .add(
      "Send application message",
      async () =>
        await createApplicationMessage({
          context: {
            cipherSuite: impl,
            authService: unsafeTestingAuthenticationService,
          },
          state: initResult.result.newState,
          message: new Uint8Array([1, 2, 3, 4, 5]),
        }),
    )
    .add(
      "Receive application message",
      async () =>
        await processMessage({
          context: {
            cipherSuite: impl,
            authService: unsafeTestingAuthenticationService,
            pskIndex: emptyPskIndex,
          },
          state: joinResult,
          message: sendMessageResult.message as any,
        }),
    )
    .add("Add member", async () => await addMember(impl, addMembersResult))
    .add(
      "Receive add member commit",
      async () =>
        await processMessage({
          context: {
            cipherSuite: impl,
            authService: unsafeTestingAuthenticationService,
            pskIndex: emptyPskIndex,
          },
          state: joinResult,
          message: addMemberResult.result.commit,
          callback: acceptAll,
        }),
    )
    .add("Remove member", async () => await removeMember(impl, initResult.result.newState))
    .add(
      "Receive remove member commit",
      async () =>
        await processMessage({
          context: {
            cipherSuite: impl,
            authService: unsafeTestingAuthenticationService,
            pskIndex: emptyPskIndex,
          },
          state: joinResult,
          message: removeMemberResult.commit,
          callback: acceptAll,
        }),
    )

  await bench.run()
  console.log(bench.name)
  console.table(bench.table())

  const results = bench.table().map(parseTable)

  fs.mkdirSync("results", { recursive: true })
  fs.writeFileSync(outputPath, JSON.stringify(results, null, 2))
}

await runBenchBasic("bench/results/basic.json", "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
await runBench("bench/results/bench.json", "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", 201)
