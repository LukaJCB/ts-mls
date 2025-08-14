import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { CiphersuiteImpl, CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite"
import { PublicKey, Hpke, encryptWithLabel, PrivateKey, decryptWithLabel } from "./crypto/hpke"
import { expandWithLabel } from "./crypto/kdf"
import { decodeGroupInfo, encodeGroupInfo, extractWelcomeSecret, GroupInfo } from "./groupInfo"
import { decodeGroupSecrets, encodeGroupSecrets, GroupSecrets } from "./groupSecrets"
import { HPKECiphertext, encodeHpkeCiphertext, decodeHpkeCiphertext } from "./hpkeCiphertext"
import { ValidationError } from "./mlsError"
import { constantTimeEqual } from "./util/constantTimeCompare"

export interface EncryptedGroupSecrets {
  newMember: Uint8Array
  encryptedGroupSecrets: HPKECiphertext
}

export const encodeEncryptedGroupSecrets: Encoder<EncryptedGroupSecrets> = contramapEncoders(
  [encodeVarLenData, encodeHpkeCiphertext],
  (egs) => [egs.newMember, egs.encryptedGroupSecrets] as const,
)

export const decodeEncryptedGroupSecrets: Decoder<EncryptedGroupSecrets> = mapDecoders(
  [decodeVarLenData, decodeHpkeCiphertext],
  (newMember, encryptedGroupSecrets) => ({ newMember, encryptedGroupSecrets }),
)

export interface Welcome {
  cipherSuite: CiphersuiteName
  secrets: EncryptedGroupSecrets[]
  encryptedGroupInfo: Uint8Array
}

export const encodeWelcome: Encoder<Welcome> = contramapEncoders(
  [encodeCiphersuite, encodeVarLenType(encodeEncryptedGroupSecrets), encodeVarLenData],
  (welcome) => [welcome.cipherSuite, welcome.secrets, welcome.encryptedGroupInfo] as const,
)

export const decodeWelcome: Decoder<Welcome> = mapDecoders(
  [decodeCiphersuite, decodeVarLenType(decodeEncryptedGroupSecrets), decodeVarLenData],
  (cipherSuite, secrets, encryptedGroupInfo) => ({ cipherSuite, secrets, encryptedGroupInfo }),
)

export function welcomeNonce(welcomeSecret: Uint8Array, cs: CiphersuiteImpl) {
  return expandWithLabel(welcomeSecret, "nonce", new Uint8Array(), cs.hpke.nonceLength, cs.kdf)
}

export function welcomeKey(welcomeSecret: Uint8Array, cs: CiphersuiteImpl) {
  return expandWithLabel(welcomeSecret, "key", new Uint8Array(), cs.hpke.keyLength, cs.kdf)
}

export async function encryptGroupInfo(
  groupInfo: GroupInfo,
  welcomeSecret: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<Uint8Array> {
  const key = await welcomeKey(welcomeSecret, cs)
  const nonce = await welcomeNonce(welcomeSecret, cs)
  const encrypted = await cs.hpke.encryptAead(key, nonce, undefined, encodeGroupInfo(groupInfo))

  return encrypted
}

export async function decryptGroupInfo(
  w: Welcome,
  joinerSecret: Uint8Array,
  pskSecret: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<GroupInfo | undefined> {
  const welcomeSecret = await extractWelcomeSecret(joinerSecret, pskSecret, cs.kdf)

  const key = await welcomeKey(welcomeSecret, cs)
  const nonce = await welcomeNonce(welcomeSecret, cs)
  const decrypted = await cs.hpke.decryptAead(key, nonce, undefined, w.encryptedGroupInfo)

  const decoded = decodeGroupInfo(decrypted, 0)
  return decoded?.[0]
}

export function encryptGroupSecrets(
  initKey: PublicKey,
  encryptedGroupInfo: Uint8Array,
  groupSecrets: GroupSecrets,
  hpke: Hpke,
) {
  return encryptWithLabel(initKey, "Welcome", encryptedGroupInfo, encodeGroupSecrets(groupSecrets), hpke)
}

export async function decryptGroupSecrets(
  initPrivateKey: PrivateKey,
  keyPackageRef: Uint8Array,
  welcome: Welcome,
  hpke: Hpke,
): Promise<GroupSecrets | undefined> {
  const secret = welcome.secrets.find((s) => constantTimeEqual(s.newMember, keyPackageRef))
  if (secret === undefined) throw new ValidationError("No matching secret found")
  const decrypted = await decryptWithLabel(
    initPrivateKey,
    "Welcome",
    welcome.encryptedGroupInfo,
    secret.encryptedGroupSecrets.kemOutput,
    secret.encryptedGroupSecrets.ciphertext,
    hpke,
  )
  return decodeGroupSecrets(decrypted, 0)?.[0]
}
