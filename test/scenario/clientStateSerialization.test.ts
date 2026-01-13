import {
  CiphersuiteName,
  ciphersuites,
  createGroup,
  Credential,
  defaultCapabilities,
  defaultCredentialTypes,
  defaultLifetime,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
} from "../../src/index.js"
import { decodeGroupState, encodeGroupState, GroupState } from "../../src/clientState.js"

test.concurrent.each(Object.keys(ciphersuites).slice(0, 1))(
  "ClientState Binary serialization round-trip %s",
  async (cs) => {
    await clientStateBinarySerializationTest(cs as CiphersuiteName)
  },
)

async function clientStateBinarySerializationTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }

  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("test-group")

  const originalState = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  let groupState: GroupState | null = null

  const { clientConfig: _config, ...firstState } = originalState

  groupState = firstState

  const binary = encodeGroupState(originalState)
  expect(binary).toBeInstanceOf(Uint8Array)
  expect(binary.byteLength).toBeGreaterThan(0)

  const decoded = decodeGroupState(binary, 0)

  if (!decoded) {
    throw new Error("binary deserialization failed unexpectedly")
  }

  expect(groupState.ratchetTree).toEqual(decoded[0].ratchetTree)
}
