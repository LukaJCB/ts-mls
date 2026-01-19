import { AuthenticationService } from "./authenticationService.js"
import { ClientConfig } from "./clientConfig.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { PskIndex } from "./pskIndex.js"

/** @public */
export interface MlsContext {
  cipherSuite: CiphersuiteImpl
  authService: AuthenticationService
  pskIndex?: PskIndex
  clientConfig?: ClientConfig
}
