import { Credential } from "./credential.js"

/** @public */
export interface AuthenticationService {
  validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<AuthenticationResult>
  validateSuccessorCredential(oldCredential: Credential, newCredential: Credential): Promise<AuthenticationResult>
  validateCredentialBatch(batch: CredentialBatch[]): Promise<AuthenticationResult>
  maxConcurrency: number
  batchSize: number
}

/** @public */
export interface CredentialBatch {
  credential: Credential
  signaturePublicKey: Uint8Array
}

/** @public */
export type AuthenticationResult = { kind: "ok" } | { kind: "error"; error: string }

/** @public */
export const unsafeTestingAuthenticationService: AuthenticationService = {
  async validateCredential(_credential: Credential, _signaturePublicKey: Uint8Array): Promise<AuthenticationResult> {
    return { kind: "ok" }
  },
  async validateCredentialBatch(_batch: CredentialBatch[]): Promise<AuthenticationResult> {
    return { kind: "ok" }
  },
  async validateSuccessorCredential(
    _oldCredential: Credential,
    _newCredential: Credential,
  ): Promise<AuthenticationResult> {
    return { kind: "ok" }
  },
  maxConcurrency: 1,
  batchSize: 32,
}
