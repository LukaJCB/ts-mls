import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./codec/variableLength.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { deriveSecret, expandWithLabel, Kdf } from "./crypto/kdf.js"
import { extractEpochSecret, extractJoinerSecret, GroupContext } from "./groupContext.js"
import { extractWelcomeSecret } from "./groupInfo.js"

/** @public */
export interface KeySchedule {
  // epochSecret: Uint8Array
  senderDataSecret: Uint8Array
  // encryptionSecret: Uint8Array
  exporterSecret: Uint8Array
  externalSecret: Uint8Array
  confirmationKey: Uint8Array
  membershipKey: Uint8Array
  resumptionPsk: Uint8Array
  epochAuthenticator: Uint8Array
  initSecret: Uint8Array
}

//TODO remove 2 arrays here once we break compatability
export const keyScheduleEncoder: BufferEncoder<KeySchedule> = contramapBufferEncoders(
  [
    varLenDataEncoder,
    varLenDataEncoder,
    varLenDataEncoder,
    varLenDataEncoder,
    varLenDataEncoder,
    varLenDataEncoder,
    varLenDataEncoder,
    varLenDataEncoder,
    varLenDataEncoder,
    varLenDataEncoder,
  ],
  (ks) =>
    [
      new Uint8Array(),
      ks.senderDataSecret,
      new Uint8Array(),
      ks.exporterSecret,
      ks.externalSecret,
      ks.confirmationKey,
      ks.membershipKey,
      ks.resumptionPsk,
      ks.epochAuthenticator,
      ks.initSecret,
    ] as const,
)

export const keyScheduleDecoder: Decoder<KeySchedule> = mapDecoders(
  [
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
    varLenDataDecoder,
  ],
  (
    _epochSecret,
    senderDataSecret,
    _encryptionSecret,
    exporterSecret,
    externalSecret,
    confirmationKey,
    membershipKey,
    resumptionPsk,
    epochAuthenticator,
    initSecret,
  ) => ({
    senderDataSecret,
    exporterSecret,
    externalSecret,
    confirmationKey,
    membershipKey,
    resumptionPsk,
    epochAuthenticator,
    initSecret,
  }),
)

export interface EpochSecrets {
  keySchedule: KeySchedule
  joinerSecret: Uint8Array
  welcomeSecret: Uint8Array
  encryptionSecret: Uint8Array
}

/** @public */
export async function mlsExporter(
  exporterSecret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
  cs: CiphersuiteImpl,
): Promise<Uint8Array> {
  const secret = await deriveSecret(exporterSecret, label, cs.kdf)

  const hash = await cs.hash.digest(context)
  return expandWithLabel(secret, "exported", hash, length, cs.kdf)
}

export async function deriveKeySchedule(
  joinerSecret: Uint8Array,
  pskSecret: Uint8Array,
  groupContext: GroupContext,
  kdf: Kdf,
): Promise<[KeySchedule, Uint8Array]> {
  const epochSecret = await extractEpochSecret(groupContext, joinerSecret, kdf, pskSecret)

  const encryptionSecret = await deriveSecret(epochSecret, "encryption", kdf)

  const keySchedule = await initializeKeySchedule(epochSecret, kdf)

  return [keySchedule, encryptionSecret] as const
}

export async function initializeKeySchedule(epochSecret: Uint8Array, kdf: Kdf): Promise<KeySchedule> {
  const newInitSecret = await deriveSecret(epochSecret, "init", kdf)
  const senderDataSecret = await deriveSecret(epochSecret, "sender data", kdf)
  const exporterSecret = await deriveSecret(epochSecret, "exporter", kdf)
  const externalSecret = await deriveSecret(epochSecret, "external", kdf)
  const confirmationKey = await deriveSecret(epochSecret, "confirm", kdf)
  const membershipKey = await deriveSecret(epochSecret, "membership", kdf)
  const resumptionPsk = await deriveSecret(epochSecret, "resumption", kdf)
  const epochAuthenticator = await deriveSecret(epochSecret, "authentication", kdf)

  const newKeySchedule: KeySchedule = {
    initSecret: newInitSecret,
    senderDataSecret,
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

  const [newKeySchedule, encryptionSecret] = await deriveKeySchedule(joinerSecret, pskSecret, groupContext, kdf)

  return { welcomeSecret, joinerSecret, encryptionSecret, keySchedule: newKeySchedule }
}
