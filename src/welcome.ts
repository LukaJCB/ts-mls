import { uint16Decoder, uint16Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder, encode } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenTypeDecoder, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { PublicKey, Hpke, encryptWithLabel, PrivateKey, decryptWithLabel } from "./crypto/hpke.js"
import { expandWithLabel } from "./crypto/kdf.js"
import { groupInfoDecoder, groupInfoEncoder, extractWelcomeSecret, GroupInfo } from "./groupInfo.js"
import { groupSecretsDecoder, GroupSecrets, groupSecretsEncoder } from "./groupSecrets.js"
import { HPKECiphertext, hpkeCiphertextEncoder, hpkeCiphertextDecoder } from "./hpkeCiphertext.js"
import { ValidationError } from "./mlsError.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"

/** @public */
export interface EncryptedGroupSecrets {
  newMember: Uint8Array
  encryptedGroupSecrets: HPKECiphertext
}

export const encryptedGroupSecretsEncoder: Encoder<EncryptedGroupSecrets> = contramapBufferEncoders(
  [varLenDataEncoder, hpkeCiphertextEncoder],
  (egs) => [egs.newMember, egs.encryptedGroupSecrets] as const,
)

export const encryptedGroupSecretsDecoder: Decoder<EncryptedGroupSecrets> = mapDecoders(
  [varLenDataDecoder, hpkeCiphertextDecoder],
  (newMember, encryptedGroupSecrets) => ({ newMember, encryptedGroupSecrets }),
)

/** @public */
export interface Welcome {
  cipherSuite: number
  secrets: EncryptedGroupSecrets[]
  encryptedGroupInfo: Uint8Array
}

export const welcomeEncoder: Encoder<Welcome> = contramapBufferEncoders(
  [uint16Encoder, varLenTypeEncoder(encryptedGroupSecretsEncoder), varLenDataEncoder],
  (welcome) => [welcome.cipherSuite, welcome.secrets, welcome.encryptedGroupInfo] as const,
)

export const welcomeDecoder: Decoder<Welcome> = mapDecoders(
  [uint16Decoder, varLenTypeDecoder(encryptedGroupSecretsDecoder), varLenDataDecoder],
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
  const encrypted = await cs.hpke.encryptAead(key, nonce, undefined, encode(groupInfoEncoder, groupInfo))

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

  const decoded = groupInfoDecoder(decrypted, 0)
  return decoded?.[0]
}

export function encryptGroupSecrets(
  initKey: PublicKey,
  encryptedGroupInfo: Uint8Array,
  groupSecrets: GroupSecrets,
  hpke: Hpke,
) {
  return encryptWithLabel(initKey, "Welcome", encryptedGroupInfo, encode(groupSecretsEncoder, groupSecrets), hpke)
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
  return groupSecretsDecoder(decrypted, 0)?.[0]
}
