import { groupActiveStateEncoder, groupActiveStateDecoder, GroupActiveState } from "../../src/groupActiveState.js"
import { createRoundtripTestBufferEncoder } from "./roundtrip.js"
import {
  CiphersuiteName,
  createGroup,
  Credential,
  defaultCredentialTypes,
  generateKeyPackage,
  getCiphersuiteImpl,
  reinitGroup,
  unsafeTestingAuthenticationService,
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
    const impl = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")

    const aliceCredential: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("alice"),
    }
    const alice = await generateKeyPackage({
      credential: aliceCredential,
      extensions: [],
      cipherSuite: impl,
    })

    const groupId = new TextEncoder().encode("group1")

    const aliceGroup = await createGroup({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      groupId,
      keyPackage: alice.publicPackage,
      privateKeyPackage: alice.privatePackage,
      extensions: [],
    })

    const newCiphersuite: CiphersuiteName = "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448"

    const newGroupId = new TextEncoder().encode("new-group1")

    const reinitCommitResult = await reinitGroup({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: aliceGroup,
      groupId: newGroupId,
      version: "mls10",
      cipherSuite: newCiphersuite,
      extensions: [],
    })

    roundtrip(reinitCommitResult.newState.groupActiveState)
  })
})
