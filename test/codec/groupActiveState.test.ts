import { groupActiveStateEncoder, groupActiveStateDecoder, GroupActiveState } from "../../src/groupActiveState.js"
import { createRoundtripTestBufferEncoder } from "./roundtrip.js"
import {
  CiphersuiteName,
  createGroup,
  Credential,
  defaultCredentialTypes,
  defaultCapabilities,
  defaultLifetime,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  reinitGroup,
} from "../../src/index.js"

describe("GroupActiveState roundtrip", () => {
  const roundtrip = createRoundtripTestBufferEncoder(groupActiveStateEncoder, groupActiveStateDecoder)

  test("roundtrips active", () => {
    const state: GroupActiveState = { kind: "active" }
    roundtrip(state)
  })

  test("roundtrips removedFromGroup", () => {
    const state: GroupActiveState = { kind: "removedFromGroup" }
    roundtrip(state)
  })

  test("roundtrips suspendedPendingReinit", async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"))

    const aliceCredential: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("alice"),
    }
    const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

    const groupId = new TextEncoder().encode("group1")

    const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

    const newCiphersuite: CiphersuiteName = "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448"

    const newGroupId = new TextEncoder().encode("new-group1")

    const reinitCommitResult = await reinitGroup(aliceGroup, newGroupId, "mls10", newCiphersuite, [], impl)

    roundtrip(reinitCommitResult.newState.groupActiveState)
  })
})
