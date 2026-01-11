import { Capabilities } from "./capabilities.js"
import { ciphersuites, CiphersuiteName } from "./crypto/ciphersuite.js"
import { greaseCapabilities, defaultGreaseConfig } from "./grease.js"

/** @public */
export function defaultCapabilities(): Capabilities {
  return greaseCapabilities(defaultGreaseConfig, {
    versions: ["mls10"],
    ciphersuites: Object.keys(ciphersuites) as CiphersuiteName[],
    extensions: [],
    proposals: [],
    credentials: ["basic", "x509"],
  })
}
