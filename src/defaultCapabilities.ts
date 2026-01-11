import { Capabilities } from "./capabilities.js"
import { credentialTypes, CredentialTypeValue } from "./credentialType.js"
import { ciphersuites, CiphersuiteId } from "./crypto/ciphersuite.js"
import { greaseCapabilities, defaultGreaseConfig } from "./grease.js"
import { protocolVersions } from "./protocolVersion.js"

/** @public */
export function defaultCapabilities(): Capabilities {
  return greaseCapabilities(defaultGreaseConfig, {
    versions: [protocolVersions.mls10],
    ciphersuites: Object.values(ciphersuites) as CiphersuiteId[],
    extensions: [],
    proposals: [],
    credentials: Object.values(credentialTypes) as CredentialTypeValue[],
  })
}
