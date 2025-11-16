import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapEncs, Enc, encode } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, encVarLenData, encVarLenType } from "./codec/variableLength.js"
import { CiphersuiteImpl, CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite.js"
import { Hash, refhash } from "./crypto/hash.js"
import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature.js"
import { decodeExtension, encodeExtension, Extension } from "./extension.js"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion.js"
import {
  decodeLeafNodeKeyPackage,
  encodeLeafNode,
  LeafNodeKeyPackage,
  LeafNodeTBSKeyPackage,
  signLeafNodeKeyPackage,
} from "./leafNode.js"
import { Capabilities } from "./capabilities.js"
import { Lifetime } from "./lifetime.js"
import { Credential } from "./credential.js"

type KeyPackageTBS = {
  version: ProtocolVersionName
  cipherSuite: CiphersuiteName
  initKey: Uint8Array
  leafNode: LeafNodeKeyPackage
  extensions: Extension[]
}

export const encodeKeyPackageTBS: Enc<KeyPackageTBS> = contramapEncs(
  [encodeProtocolVersion, encodeCiphersuite, encVarLenData, encodeLeafNode, encVarLenType(encodeExtension)],
  (keyPackageTBS) =>
    [
      keyPackageTBS.version,
      keyPackageTBS.cipherSuite,
      keyPackageTBS.initKey,
      keyPackageTBS.leafNode,
      keyPackageTBS.extensions,
    ] as const,
)

export const decodeKeyPackageTBS: Decoder<KeyPackageTBS> = mapDecoders(
  [
    decodeProtocolVersion,
    decodeCiphersuite,
    decodeVarLenData,
    decodeLeafNodeKeyPackage,
    decodeVarLenType(decodeExtension),
  ],
  (version, cipherSuite, initKey, leafNode, extensions) => ({
    version,
    cipherSuite,
    initKey,
    leafNode,
    extensions,
  }),
)

export type KeyPackage = KeyPackageTBS & { signature: Uint8Array }

export const encodeKeyPackage: Enc<KeyPackage> = contramapEncs(
  [encodeKeyPackageTBS, encVarLenData],
  (keyPackage) => [keyPackage, keyPackage.signature] as const,
)

export const decodeKeyPackage: Decoder<KeyPackage> = mapDecoders(
  [decodeKeyPackageTBS, decodeVarLenData],
  (keyPackageTBS, signature) => ({
    ...keyPackageTBS,
    signature,
  }),
)

export async function signKeyPackage(tbs: KeyPackageTBS, signKey: Uint8Array, s: Signature): Promise<KeyPackage> {
  return { ...tbs, signature: await signWithLabel(signKey, "KeyPackageTBS", encode(encodeKeyPackageTBS)(tbs), s) }
}

export async function verifyKeyPackage(kp: KeyPackage, s: Signature): Promise<boolean> {
  return verifyWithLabel(kp.leafNode.signaturePublicKey, "KeyPackageTBS", encode(encodeKeyPackageTBS)(kp), kp.signature, s)
}

export function makeKeyPackageRef(value: KeyPackage, h: Hash): Promise<Uint8Array> {
  return refhash("MLS 1.0 KeyPackage Reference", encode(encodeKeyPackage)(value), h)
}

export interface PrivateKeyPackage {
  initPrivateKey: Uint8Array
  hpkePrivateKey: Uint8Array
  signaturePrivateKey: Uint8Array
}

export async function generateKeyPackageWithKey(
  credential: Credential,
  capabilities: Capabilities,
  lifetime: Lifetime,
  extensions: Extension[],
  signatrueKeyPair: { signKey: Uint8Array; publicKey: Uint8Array },
  cs: CiphersuiteImpl,
): Promise<{ publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }> {
  const initKeys = await cs.hpke.generateKeyPair()
  const hpkeKeys = await cs.hpke.generateKeyPair()

  const privatePackage = {
    initPrivateKey: await cs.hpke.exportPrivateKey(initKeys.privateKey),
    hpkePrivateKey: await cs.hpke.exportPrivateKey(hpkeKeys.privateKey),
    signaturePrivateKey: signatrueKeyPair.signKey,
  }

  const leafNodeTbs: LeafNodeTBSKeyPackage = {
    leafNodeSource: "key_package",
    hpkePublicKey: await cs.hpke.exportPublicKey(hpkeKeys.publicKey),
    signaturePublicKey: signatrueKeyPair.publicKey,
    info: { leafNodeSource: "key_package" },
    extensions,
    credential,
    capabilities,
    lifetime,
  }

  const tbs: KeyPackageTBS = {
    version: "mls10",
    cipherSuite: cs.name,
    initKey: await cs.hpke.exportPublicKey(initKeys.publicKey),
    leafNode: await signLeafNodeKeyPackage(leafNodeTbs, signatrueKeyPair.signKey, cs.signature),
    extensions,
  }

  return { publicPackage: await signKeyPackage(tbs, signatrueKeyPair.signKey, cs.signature), privatePackage }
}

export async function generateKeyPackage(
  credential: Credential,
  capabilities: Capabilities,
  lifetime: Lifetime,
  extensions: Extension[],
  cs: CiphersuiteImpl,
): Promise<{ publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }> {
  const sigKeys = await cs.signature.keygen()
  return generateKeyPackageWithKey(credential, capabilities, lifetime, extensions, sigKeys, cs)
}
