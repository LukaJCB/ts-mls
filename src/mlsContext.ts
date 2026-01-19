import { AuthenticationService } from "./authenticationService.js"
import { ClientConfig } from "./clientConfig.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"

/** @public */
export interface MlsContext {
  cipherSuite: CiphersuiteImpl
  authService: AuthenticationService
  externalPsks?: Record<string, Uint8Array>
  clientConfig?: ClientConfig
}
