import { Credential } from "./credential.js"

/** @public */
export interface AuthenticationService {
  validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<boolean>
  validateSuccessorCredential(oldCredential: Credential, newCredential: Credential): Promise<boolean>
}

/** @public */
export const unsafeTestingAuthenticationService: AuthenticationService = {
  async validateCredential(_credential: Credential, _signaturePublicKey: Uint8Array): Promise<boolean> {
    return true
  },
  async validateSuccessorCredential(_oldCredential: Credential, _newCredential: Credential): Promise<boolean> {
    return true
  },
}
