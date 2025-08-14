import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { Credential, decodeCredential, encodeCredential } from "./credential"

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
