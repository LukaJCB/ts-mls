import { Credential } from "./credential.js"

/** @public */
export interface AuthenticationService {
  validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<boolean>
}

/** @public */
export const unsafeTestingAuthenticationService: AuthenticationService = {
  async validateCredential(_credential: Credential, _signaturePublicKey: Uint8Array): Promise<boolean> {
    return true
  },
}
