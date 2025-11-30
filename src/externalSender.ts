import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { Credential, decodeCredential, credentialEncoder } from "./credential.js"

export interface ExternalSender {
  signaturePublicKey: Uint8Array
  credential: Credential
}

export const externalSenderEncoder: BufferEncoder<ExternalSender> = contramapBufferEncoders(
  [varLenDataEncoder, credentialEncoder],
  (e) => [e.signaturePublicKey, e.credential] as const,
)

export const encodeExternalSender: Encoder<ExternalSender> = encode(externalSenderEncoder)

export const decodeExternalSender: Decoder<ExternalSender> = mapDecoders(
  [decodeVarLenData, decodeCredential],
  (signaturePublicKey, credential) => ({ signaturePublicKey, credential }),
)
