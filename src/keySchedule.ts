import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { deriveSecret, expandWithLabel, Kdf } from "./crypto/kdf"
import { extractEpochSecret, extractJoinerSecret, GroupContext } from "./groupContext"
import { extractWelcomeSecret } from "./groupInfo"

export interface KeySchedule {
  epochSecret: Uint8Array
  senderDataSecret: Uint8Array
  encryptionSecret: Uint8Array
  exporterSecret: Uint8Array
  externalSecret: Uint8Array
  confirmationKey: Uint8Array
  membershipKey: Uint8Array
  resumptionPsk: Uint8Array
  epochAuthenticator: Uint8Array
  initSecret: Uint8Array
}

export interface EpochSecrets {
  keySchedule: KeySchedule
  joinerSecret: Uint8Array
  welcomeSecret: Uint8Array
}

export async function mlsExporter(
  exporterSecret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
  cs: CiphersuiteImpl,
) {
  const secret = await deriveSecret(exporterSecret, label, cs.kdf)

  const hash = await cs.hash.digest(context)
  return expandWithLabel(secret, "exported", hash, length, cs.kdf)
}

export async function deriveKeySchedule(
  joinerSecret: Uint8Array,
  pskSecret: Uint8Array,
  groupContext: GroupContext,
  kdf: Kdf,
) {
  const epochSecret = await extractEpochSecret(groupContext, joinerSecret, kdf, pskSecret)

  return await initializeKeySchedule(epochSecret, kdf)
}

export async function initializeKeySchedule(epochSecret: Uint8Array, kdf: Kdf): Promise<KeySchedule> {
  const newInitSecret = await deriveSecret(epochSecret, "init", kdf)
  const senderDataSecret = await deriveSecret(epochSecret, "sender data", kdf)
  const encryptionSecret = await deriveSecret(epochSecret, "encryption", kdf)
  const exporterSecret = await deriveSecret(epochSecret, "exporter", kdf)
  const externalSecret = await deriveSecret(epochSecret, "external", kdf)
  const confirmationKey = await deriveSecret(epochSecret, "confirm", kdf)
  const membershipKey = await deriveSecret(epochSecret, "membership", kdf)
  const resumptionPsk = await deriveSecret(epochSecret, "resumption", kdf)
  const epochAuthenticator = await deriveSecret(epochSecret, "authentication", kdf)

  const newKeySchedule: KeySchedule = {
    epochSecret: epochSecret,
    initSecret: newInitSecret,
    senderDataSecret,
    encryptionSecret,
    exporterSecret,
    externalSecret,
    confirmationKey,
    membershipKey,
    resumptionPsk,
    epochAuthenticator,
  }

  return newKeySchedule
}

export async function initializeEpoch(
  initSecret: Uint8Array,
  commitSecret: Uint8Array,
  groupContext: GroupContext,
  pskSecret: Uint8Array,
  kdf: Kdf,
): Promise<EpochSecrets> {
  const joinerSecret = await extractJoinerSecret(groupContext, initSecret, commitSecret, kdf)

  const welcomeSecret = await extractWelcomeSecret(joinerSecret, pskSecret, kdf)

  const newKeySchedule: KeySchedule = await deriveKeySchedule(joinerSecret, pskSecret, groupContext, kdf)

  return { welcomeSecret, joinerSecret, keySchedule: newKeySchedule }
}
