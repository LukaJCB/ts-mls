import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { Credential, credentialDecoder, credentialEncoder } from "./credential.js"

/** @public */
export interface ExternalSender {
  signaturePublicKey: Uint8Array
  credential: Credential
}

export const externalSenderEncoder: Encoder<ExternalSender> = contramapBufferEncoders(
  [varLenDataEncoder, credentialEncoder],
  (e) => [e.signaturePublicKey, e.credential] as const,
)

export const externalSenderDecoder: Decoder<ExternalSender> = mapDecoders(
  [varLenDataDecoder, credentialDecoder],
  (signaturePublicKey, credential) => ({ signaturePublicKey, credential }),
)
