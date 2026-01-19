import { ClientState } from "../../src/clientState.js"
import { createApplicationMessage } from "../../src/createMessage.js"
import { processMessage } from "../../src/processMessages.js"
import { CiphersuiteImpl } from "../../src/crypto/ciphersuite.js"
import { UsageError } from "../../src/mlsError.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

export async function testEveryoneCanMessageEveryone(
  clients: ClientState[],
  impl: CiphersuiteImpl,
): Promise<{ updatedGroups: ClientState[] }> {
  const encoder = new TextEncoder()
  const updatedGroups = [...clients]

  for (const [senderIndex, senderState] of updatedGroups.entries()) {
    const messageText = `Hello from member ${senderIndex}`
    const encodedMessage = encoder.encode(messageText)

    const { message, newState: newSenderState } = await createApplicationMessage({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state: senderState,
      message: encodedMessage,
    })
    updatedGroups[senderIndex] = newSenderState

    for (const [receiverIndex, receiverGroup] of updatedGroups.entries()) {
      if (receiverIndex === senderIndex) continue

      const result = await processMessage({
        context: {
          cipherSuite: impl,
          authService: unsafeTestingAuthenticationService,
        },
        state: receiverGroup,
        message,
      })

      if (result.kind === "newState") {
        throw new Error(`Expected application message for member ${receiverIndex} from ${senderIndex}`)
      }

      expect(result.message).toStrictEqual(encodedMessage)

      updatedGroups[receiverIndex] = result.newState
    }
  }

  return { updatedGroups }
}

export async function cannotMessageAnymore(state: ClientState, impl: CiphersuiteImpl): Promise<void> {
  await expect(
    createApplicationMessage({
      context: { cipherSuite: impl, authService: unsafeTestingAuthenticationService },
      state,
      message: new TextEncoder().encode("hello"),
    }),
  ).rejects.toThrow(UsageError)
}

export function shuffledIndices<T>(arr: T[]): number[] {
  const indices = arr.map((_, i) => i)

  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[indices[i], indices[j]] = [indices[j]!, indices[i]!]
  }

  return indices
}
export function getRandomElement<T>(arr: T[]): T {
  const index = Math.floor(Math.random() * arr.length)
  return arr[index]!
}
