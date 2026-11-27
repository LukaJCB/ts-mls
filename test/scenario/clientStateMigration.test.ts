import {
  base64ToBytes,
  CiphersuiteName,
  ClientState,
  CodecError,
  createApplicationMessage,
  createCommit,
  defaultExtensionTypes,
  decode,
  decodeClientStateV1,
  encode,
  getCiphersuiteImpl,
  clientStateDecoder,
  clientStateEncoder,
  mlsMessageDecoder,
  MlsFramedMessage,
  processMessage,
  unsafeTestingAuthenticationService,
  UsageError,
  wireformats,
} from "../../src/index.js"
import fixtures from "../fixtures/client-state-v1/states.json"

function message(value: string): MlsFramedMessage {
  const decoded = decode(mlsMessageDecoder, base64ToBytes(value))!
  if (decoded.wireformat !== wireformats.mls_private_message && decoded.wireformat !== wireformats.mls_public_message) {
    throw new Error("Expected a framed message")
  }
  return decoded
}

describe.each(fixtures)("$version ClientState migration ($cipherSuite)", (fixture) => {
  const context = async () => {
    const impl = await getCiphersuiteImpl(fixture.cipherSuite as CiphersuiteName)
    // Experimental 1.x suites used different IDs. Preserve the group's wire ID.
    return { cipherSuite: { ...impl, id: fixture.cipherSuiteId }, authService: unsafeTestingAuthenticationService }
  }

  test("migrates a singleton and persists it in the 2.x encoding", async () => {
    const ctx = await context()
    const state = await decodeClientStateV1({
      encodedState: base64ToBytes(fixture.initialState),
      cipherSuite: ctx.cipherSuite,
    })
    expect(state.secretTree.leafWidth).toBe(1)
    expect(Object.keys(state.secretTree.leafNodes)).toEqual(["0"])
    expect(state.historicalReceiverData.size).toBe(0)
    expect(state.groupContext.extensions).toEqual([
      {
        extensionType: defaultExtensionTypes.required_capabilities,
        extensionData: { extensionTypes: [0xff00], proposalTypes: [], credentialTypes: [1] },
      },
      { extensionType: 0xff00, extensionData: new TextEncoder().encode("custom extension") },
    ])
    expect(Object.values({ ...state.keySchedule }).every((secret) => secret.length === ctx.cipherSuite.kdf.size)).toBe(
      true,
    )
    expect(decode(clientStateDecoder, encode(clientStateEncoder, state))).toEqual(state)
    await expect(
      createApplicationMessage({ context: ctx, state, message: new TextEncoder().encode("after migration") }),
    ).resolves.toBeDefined()
  })

  test("preserves generations, pending proposals and historical epochs without modifying the input", async () => {
    const ctx = await context()
    const encodedState = base64ToBytes(fixture.aliceState)
    const originalBytes = encodedState.slice()
    const state = await decodeClientStateV1({ encodedState, cipherSuite: ctx.cipherSuite })
    expect(encodedState).toEqual(originalBytes)
    expect(state.groupContext.epoch).toBe(2n)
    expect(state.secretTree.leafWidth).toBe(4)
    expect(Object.keys(state.secretTree.leafNodes)).toEqual(["0", "2", "4", "6"])
    expect(state.secretTree.intermediateNodes).toEqual({})
    expect(state.secretTree.leafNodes[2]!.application.generation).toBe(3)
    expect(Object.keys(state.secretTree.leafNodes[2]!.application.unusedGenerations)).toEqual(["0", "1"])
    expect(state.secretTree.leafNodes[2]!.handshake.generation).toBe(2)
    expect(Object.keys(state.secretTree.leafNodes[2]!.handshake.unusedGenerations)).toEqual(["0"])
    expect(Object.keys(state.unappliedProposals)).toHaveLength(1)
    expect([...state.historicalReceiverData.keys()]).toEqual([0n, 1n])
    expect(state.treeHashCache).toEqual([])
    expect(decode(clientStateDecoder, encode(clientStateEncoder, state))).toEqual(state)
  })

  test("decrypts retained current and historical generations and continues the receiving ratchet", async () => {
    const ctx = await context()
    let state = await decodeClientStateV1({
      encodedState: base64ToBytes(fixture.aliceState),
      cipherSuite: ctx.cipherSuite,
    })
    for (const [encoded, plaintext] of [
      [fixture.historicalDelayed, "historical generation 0"],
      [fixture.delayed, "current generation 0"],
      [fixture.next, "current generation 3"],
    ] as const) {
      const incoming = message(encoded)
      const result = await processMessage({ context: ctx, state, message: incoming })
      if (result.kind !== "applicationMessage") throw new Error("Expected application message")
      expect(new TextDecoder().decode(result.message)).toBe(plaintext)
      state = result.newState
      await expect(processMessage({ context: ctx, state, message: incoming })).rejects.toThrow(
        "Desired gen in the past",
      )
    }
    await expect(processMessage({ context: ctx, state, message: message(fixture.alreadyReceived) })).rejects.toThrow(
      "Desired gen in the past",
    )
  })

  test("decrypts a skipped handshake generation", async () => {
    const ctx = await context()
    const state = await decodeClientStateV1({
      encodedState: base64ToBytes(fixture.aliceState),
      cipherSuite: ctx.cipherSuite,
    })
    const incoming = message(fixture.delayedProposal)
    const result = await processMessage({ context: ctx, state, message: incoming })
    expect(result.kind).toBe("newState")
    expect(Object.keys(result.newState.unappliedProposals)).toHaveLength(2)
    expect(result.newState.secretTree.leafNodes[2]!.handshake.unusedGenerations).toEqual({})
    await expect(processMessage({ context: ctx, state: result.newState, message: incoming })).rejects.toThrow(
      "Desired gen in the past",
    )
  })

  test("continues the sending ratchet", async () => {
    const ctx = await context()
    const migrate = (value: string) =>
      decodeClientStateV1({ encodedState: base64ToBytes(value), cipherSuite: ctx.cipherSuite })
    const [alice, bob] = await Promise.all([migrate(fixture.aliceBeforeProposals), migrate(fixture.bobBeforeProposals)])
    expect(alice.secretTree.leafNodes[0]!.application.generation).toBe(1)
    const sent = await createApplicationMessage({ context: ctx, state: alice, message: new Uint8Array([99]) })
    expect(sent.newState.secretTree.leafNodes[0]!.application.generation).toBe(2)
    const received = await processMessage({ context: ctx, state: bob, message: sent.message })
    if (received.kind !== "applicationMessage") throw new Error("Expected application message")
    expect(received.message).toEqual(new Uint8Array([99]))
  })

  test("commits a saved pending proposal and exchanges messages with a migrated peer", async () => {
    const ctx = await context()
    const migrate = (value: string) =>
      decodeClientStateV1({ encodedState: base64ToBytes(value), cipherSuite: ctx.cipherSuite })
    const [alice, bob] = await Promise.all([migrate(fixture.aliceState), migrate(fixture.bobState)])
    const committed = await createCommit({ context: ctx, state: alice })
    const accepted = await processMessage({ context: ctx, state: bob, message: committed.commit })
    expect(accepted.kind).toBe("newState")
    expect(accepted.newState.groupContext).toEqual(committed.newState.groupContext)
    expect(accepted.newState.keySchedule.epochAuthenticator).toEqual(committed.newState.keySchedule.epochAuthenticator)
    expect(committed.newState.groupContext.epoch).toBe(3n)
    expect(committed.newState.ratchetTree).toHaveLength(3)
    expect(committed.newState.unappliedProposals).toEqual({})
    const members: ClientState[] = [committed.newState, accepted.newState]
    for (const [sender, receiver] of [members, [...members].reverse()]) {
      const sent = await createApplicationMessage({ context: ctx, state: sender!, message: new Uint8Array([42]) })
      const received = await processMessage({ context: ctx, state: receiver!, message: sent.message })
      if (received.kind !== "applicationMessage") throw new Error("Expected application message")
      expect(received.message).toEqual(new Uint8Array([42]))
    }
  })

  test.each(["removedState", "suspendedState"] as const)("preserves %s", async (field) => {
    const ctx = await context()
    const state = await decodeClientStateV1({
      encodedState: base64ToBytes(fixture[field]),
      cipherSuite: ctx.cipherSuite,
    })
    expect(state.groupActiveState.kind).toBe(field === "removedState" ? "removedFromGroup" : "suspendedPendingReinit")
    expect(decode(clientStateDecoder, encode(clientStateEncoder, state))).toEqual(state)
    await expect(createCommit({ context: ctx, state })).rejects.toThrow(UsageError)
  })

  test("rejects the non-RFC 1.x external_senders format", async () => {
    const ctx = await context()
    await expect(
      decodeClientStateV1({
        encodedState: base64ToBytes(fixture.legacyExternalSendersState),
        cipherSuite: ctx.cipherSuite,
      }),
    ).rejects.toThrow(CodecError)
  })
})

test("rejects incomplete, trailing, oversized, and mismatched state encodings", async () => {
  const fixture = fixtures[0]!
  const cipherSuite = await getCiphersuiteImpl(fixture.cipherSuite as CiphersuiteName)
  const encodedState = base64ToBytes(fixture.aliceState)
  for (const invalid of [new Uint8Array(), encodedState.slice(0, -1), new Uint8Array([...encodedState, 0])]) {
    await expect(decodeClientStateV1({ encodedState: invalid, cipherSuite })).rejects.toThrow(CodecError)
  }
  await expect(
    decodeClientStateV1({ encodedState, cipherSuite, maxInputSize: encodedState.length - 1 }),
  ).rejects.toThrow(CodecError)
  await expect(decodeClientStateV1({ encodedState, cipherSuite: { ...cipherSuite, id: 2 } })).rejects.toThrow(
    UsageError,
  )
})
