import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength.js"
import { Credential, decodeCredential, encodeCredential } from "./credential.js"

export interface ExternalSender {
  signaturePublicKey: Uint8Array
  credential: Credential
}

export const encodeExternalSender: Encoder<ExternalSender> = contramapEncoders(
  [encodeVarLenData, encodeCredential],
  (e) => [e.signaturePublicKey, e.credential] as const,
)

export const decodeExternalSender: Decoder<ExternalSender> = mapDecoders(
  [decodeVarLenData, decodeCredential],
  (signaturePublicKey, credential) => ({ signaturePublicKey, credential }),
)
