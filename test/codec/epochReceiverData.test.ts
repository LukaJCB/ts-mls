import { addHistoricalReceiverData } from "../../src/clientState.js"
import { bigintMapEncoder, bigintMapDecoder } from "../../src/codec/variableLength.js"
import { epochReceiverDataDecoder, epochReceiverDataEncoder } from "../../src/epochReceiverData.js"
import {
  createGroup,
  defaultCapabilities,
  defaultCredentialTypes,
  defaultLifetime,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  unsafeTestingAuthenticationService,
} from "../../src/index.js"
import { createRoundtripTestBufferEncoder } from "./roundtrip.js"

describe("EpochReceiverData roundtrip", () => {
  const roundtripEpochReceiverData = createRoundtripTestBufferEncoder(
    epochReceiverDataEncoder,
    epochReceiverDataDecoder,
  )

  const roundtripEpochReceiverDataMap = createRoundtripTestBufferEncoder(
    bigintMapEncoder(epochReceiverDataEncoder),
    bigintMapDecoder(epochReceiverDataDecoder),
  )

  test("roundtrips epoch receiver data extracted from client state", async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))

    const aliceCredential = {
      credentialType: defaultCredentialTypes.basic,
      identity: new TextEncoder().encode("alice"),
    }

    const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

    const groupId = new TextEncoder().encode("test-group")

    const state = await createGroup(
      groupId,
      alice.publicPackage,
      alice.privatePackage,
      [],
      unsafeTestingAuthenticationService,
      impl,
    )

    const [historical] = addHistoricalReceiverData(state)

    expect(historical.size).toBeGreaterThan(0)

    for (const [, epochData] of historical) {
      roundtripEpochReceiverData(epochData)
    }

    roundtripEpochReceiverDataMap(historical)
  })
})
