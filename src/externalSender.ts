import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapEncs, Enc } from "./codec/tlsEncoder.js"
import { decodeVarLenData, encVarLenData } from "./codec/variableLength.js"
import { Credential, decodeCredential, encodeCredential } from "./credential.js"

export interface ExternalSender {
  signaturePublicKey: Uint8Array
  credential: Credential
}

export const encodeExternalSender: Enc<ExternalSender> = contramapEncs(
  [encVarLenData, encodeCredential],
  (e) => [e.signaturePublicKey, e.credential] as const,
)

export const decodeExternalSender: Decoder<ExternalSender> = mapDecoders(
  [decodeVarLenData, decodeCredential],
  (signaturePublicKey, credential) => ({ signaturePublicKey, credential }),
)
