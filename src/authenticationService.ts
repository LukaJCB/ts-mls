import { Credential } from "./credential.js"

/** @public */
export interface AuthenticationService {
  validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<AuthenticationResult>
  validateSuccessorCredential(
    oldCredential: CredentialWithKey,
    newCredential: CredentialWithKey,
  ): Promise<AuthenticationResult>
  validateCredentialBatch(batches: CredentialBatchItem[][]): Promise<AuthenticationResult>
  batchSize: number
}

/** @public */
export interface CredentialBatchItem {
  credential: Credential
  signaturePublicKey: Uint8Array
  oldCredential?: CredentialWithKey
}

/** @public */
export interface CredentialWithKey {
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
  async validateCredentialBatch(_batches: CredentialWithKey[][]): Promise<AuthenticationResult> {
    return { kind: "ok" }
  },
  async validateSuccessorCredential(
    _oldCredential: CredentialWithKey,
    _newCredential: CredentialWithKey,
  ): Promise<AuthenticationResult> {
    return { kind: "ok" }
  },
  batchSize: 32,
}
