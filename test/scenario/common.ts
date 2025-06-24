import { Capabilities } from "../../src/capabilities"
import { ClientState, makePskIndex } from "../../src/clientState"
import { createApplicationMessage } from "../../src/createMessage"
import { processPrivateMessage } from "../../src/processMessages"
import { CiphersuiteName, CiphersuiteImpl, ciphersuites } from "../../src/crypto/ciphersuite"
import { Lifetime } from "../../src/lifetime"

export async function testEveryoneCanMessageEveryone(clients: ClientState[], impl: CiphersuiteImpl) {
  const encoder = new TextEncoder()
  const updatedGroups = [...clients]

  for (const [senderIndex, senderState] of updatedGroups.entries()) {
    const messageText = `Hello from member ${senderIndex}`
    const encodedMessage = encoder.encode(messageText)

    const { privateMessage, newState: newSenderState } = await createApplicationMessage(
      senderState,
      encodedMessage,
      impl,
    )
    updatedGroups[senderIndex] = newSenderState

    for (const [receiverIndex, receiverGroup] of updatedGroups.entries()) {
      if (receiverIndex === senderIndex) continue

      const result = await processPrivateMessage(receiverGroup, privateMessage, makePskIndex(receiverGroup, {}), impl)

      if (result.kind === "newState") {
        throw new Error(`Expected application message for member ${receiverIndex} from ${senderIndex}`)
      }

      expect(result.message).toStrictEqual(encodedMessage)

      updatedGroups[receiverIndex] = result.newState
    }
  }

  return { updatedGroups }
}
export const defaultCapabilities: Capabilities = {
  versions: ["mls10"],
  ciphersuites: Object.keys(ciphersuites) as CiphersuiteName[],
  extensions: ["ratchet_tree"],
  proposals: [],
  credentials: ["basic", "x509"],
}
export const defaultLifetime: Lifetime = {
  notBefore: 0n,
  notAfter: 9223372036854775807n,
}
