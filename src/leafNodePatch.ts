import { Capabilities } from "./capabilities.js"
import { SignatureKeyPair } from "./signatureKeyPair.js"
import { Credential } from "./credential.js"
import { LeafNodeExtension } from "./extension.js"

/** @public */
export interface LeafNodePatch {
  extensions?: LeafNodeExtension[]
  signatureKeyPair?: SignatureKeyPair
  capabilities?: Capabilities
  credential?: Credential
}
