import {
  ciphersuites,
  type CiphersuiteName,
  decode,
  mlsMessageDecoder,
  type KeyPackage,
  type Welcome,
  type ClientState,
  nodeTypes,
  isDefaultCredential,
  defaultCredentialTypes,
  defaultExtensionTypes,
  wireformats,
  type MlsFramedMessage,
  type GroupContextExtension,
  type GroupInfoExtension,
  makeCustomExtension,
  type GroupInfo,
  type PskId,
  type PskInfoExternal,
  type PskInfoResumption,
  pskTypes,
  resumptionPSKUsages,
  bytesToBase64,
} from "../../src/index.js"
import { requiredCapabilitiesDecoder } from "../../src/requiredCapabilities.js"
import { fastEqual } from "../../src/util/byteArray.js"
import { externalSenderDecoder } from "../../src/externalSender.js"

export function ciphersuiteNameFromId(id: number): CiphersuiteName {
  for (const [name, value] of Object.entries(ciphersuites) as [CiphersuiteName, number][]) {
    if (value === id) return name
  }
  throw new Error(`Unsupported ciphersuite id: ${id}`)
}

export function decodeKeyPackageMessage(bytes: Uint8Array): KeyPackage {
  const msg = decode(mlsMessageDecoder, bytes)
  if (!msg) throw new Error("Failed to decode MlsMessage")
  if (msg.wireformat !== wireformats.mls_key_package) {
    throw new Error(`Expected KeyPackage wireformat, got ${msg.wireformat}`)
  }
  return msg.keyPackage
}

export function decodeWelcomeMessage(bytes: Uint8Array): Welcome {
  const msg = decode(mlsMessageDecoder, bytes)
  if (!msg) throw new Error("Failed to decode MlsMessage")
  if (msg.wireformat !== wireformats.mls_welcome) {
    throw new Error(`Expected Welcome wireformat, got ${msg.wireformat}`)
  }
  return msg.welcome
}

export function decodeFramedMessage(bytes: Uint8Array): MlsFramedMessage {
  const msg = decode(mlsMessageDecoder, bytes)
  if (!msg) throw new Error("Failed to decode MlsMessage")
  if (msg.wireformat !== wireformats.mls_private_message && msg.wireformat !== wireformats.mls_public_message) {
    throw new Error(`Expected framed message, got wireformat ${msg.wireformat}`)
  }
  return msg
}

export function decodeGroupInfo(bytes: Uint8Array): GroupInfo {
  const framed = decode(mlsMessageDecoder, bytes)
  if (framed && framed.wireformat === wireformats.mls_group_info) return framed.groupInfo
  else throw new Error("Failed to decode GroupInfo")
}

export function leafIndexForIdentity(state: ClientState, identity: Uint8Array): number {
  for (let i = 0; i < state.ratchetTree.length; i++) {
    const node = state.ratchetTree[i]
    if (!node || node.nodeType !== nodeTypes.leaf) continue
    const cred = node.leaf.credential
    if (!isDefaultCredential(cred)) continue
    if (cred.credentialType !== defaultCredentialTypes.basic) continue
    if (fastEqual(cred.identity, identity)) {
      return i / 2
    }
  }
  throw new Error(`No member with identity: ${new TextDecoder().decode(identity)}`)
}

export function toGroupContextExtension(ext: {
  extension_type: number
  extension_data: Uint8Array
}): GroupContextExtension {
  if (ext.extension_type === defaultExtensionTypes.external_senders) {
    const sender = decode(externalSenderDecoder, ext.extension_data)
    if (!sender) throw new Error("Failed to decode ExternalSender from extension_data")
    return { extensionType: defaultExtensionTypes.external_senders, extensionData: sender }
  }
  if (ext.extension_type === defaultExtensionTypes.required_capabilities) {
    const rc = decode(requiredCapabilitiesDecoder, ext.extension_data)
    if (!rc) throw new Error("Failed to decode RequiredCapabilities from extension_data")
    return { extensionType: defaultExtensionTypes.required_capabilities, extensionData: rc }
  }
  return makeCustomExtension({ extensionType: ext.extension_type, extensionData: ext.extension_data })
}

export function toGroupInfoExtension(ext: { extension_type: number; extension_data: Uint8Array }): GroupInfoExtension {
  if (ext.extension_type === defaultExtensionTypes.ratchet_tree) {
    return { extensionType: defaultExtensionTypes.ratchet_tree, extensionData: ext.extension_data }
  }
  if (ext.extension_type === defaultExtensionTypes.external_pub) {
    return { extensionType: defaultExtensionTypes.external_pub, extensionData: ext.extension_data }
  }
  return makeCustomExtension({ extensionType: ext.extension_type, extensionData: ext.extension_data })
}

export function externalPskId(
  pskId: Uint8Array,
  nonceSize: number,
  rng: { randomBytes: (n: number) => Uint8Array },
): PskId {
  const info: PskInfoExternal = { psktype: pskTypes.external, pskId }
  return { ...info, pskNonce: rng.randomBytes(nonceSize) }
}

export function resumptionPskId(
  state: ClientState,
  epoch: bigint,
  nonceSize: number,
  rng: { randomBytes: (n: number) => Uint8Array },
): PskId {
  const info: PskInfoResumption = {
    psktype: pskTypes.resumption,
    usage: resumptionPSKUsages.application,
    pskGroupId: state.groupContext.groupId,
    pskEpoch: epoch,
  }
  return { ...info, pskNonce: rng.randomBytes(nonceSize) }
}

export function pskStoreKey(pskId: Uint8Array): string {
  return bytesToBase64(pskId)
}

export interface ProtoExtension {
  extension_type: number
  extension_data: Uint8Array
}
