import { Capabilities } from "./capabilities.js"
import { ciphersuites, CiphersuiteId } from "./crypto/ciphersuite.js"
import { greaseCapabilities, defaultGreaseConfig } from "./grease.js"

/** @public */
export function defaultCapabilities(): Capabilities {
  return greaseCapabilities(defaultGreaseConfig, {
    versions: ["mls10"],
    ciphersuites: Object.values(ciphersuites) as CiphersuiteId[],
    extensions: [],
    proposals: [],
    credentials: ["basic", "x509"],
  })
}
