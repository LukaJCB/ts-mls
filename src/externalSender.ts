import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { Credential, credentialDecoder, credentialEncoder } from "./credential.js"

/** @public */
export interface ExternalSender {
  signaturePublicKey: Uint8Array
  credential: Credential
}

/** @public */
export const externalSenderEncoder: BufferEncoder<ExternalSender> = contramapBufferEncoders(
  [varLenDataEncoder, credentialEncoder],
  (e) => [e.signaturePublicKey, e.credential] as const,
)

/** @public */
export const externalSenderDecoder: Decoder<ExternalSender> = mapDecoders(
  [varLenDataDecoder, credentialDecoder],
  (signaturePublicKey, credential) => ({ signaturePublicKey, credential }),
)
