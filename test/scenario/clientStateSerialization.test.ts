import { createGroup } from "../../src/clientState.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteName, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { ClientConfig, defaultClientConfig } from "../../src/clientConfig.js"
import { fromJsonString, toJsonString } from "../../src/codec/json.js"

test.concurrent.each(Object.keys(ciphersuites))("ClientState serialization round-trip %s", async (cs) => {
  await clientStateSerializationTest(cs as CiphersuiteName)
})

async function clientStateSerializationTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = {
    credentialType: "basic",
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("test-group")

  const clientConfig: ClientConfig = defaultClientConfig

  const originalState = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)
  const { clientConfig: _config, ...firstState } = originalState

  const jsonString = toJsonString(originalState)
  expect(typeof jsonString).toBe("string")

  const deserializedState = fromJsonString(jsonString, clientConfig)
  expect(deserializedState).toBeDefined()
  expect(deserializedState).not.toBeNull()

  if (!deserializedState) {
    throw new Error("deserialization failed unexpectedly")
  }

  const { clientConfig: __config, ...secondState } = deserializedState

  expect(firstState).toEqual(secondState)
}
