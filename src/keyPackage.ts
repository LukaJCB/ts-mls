import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder, encode } from "./codec/tlsEncoder.js"
import { varLenDataDecoder, varLenTypeDecoder, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CiphersuiteId, CiphersuiteImpl, ciphersuiteEncoder, ciphersuiteDecoder } from "./crypto/ciphersuite.js"
import { Hash, refhash } from "./crypto/hash.js"
import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature.js"
import { extensionDecoder, extensionEncoder, Extension } from "./extension.js"
import {
  protocolVersionDecoder,
  protocolVersionEncoder,
  protocolVersions,
  ProtocolVersionValue,
} from "./protocolVersion.js"
import {
  leafNodeKeyPackageDecoder,
  leafNodeEncoder,
  LeafNodeKeyPackage,
  LeafNodeTBSKeyPackage,
  signLeafNodeKeyPackage,
} from "./leafNode.js"
import { leafNodeSources } from "./leafNodeSource.js"
import { Capabilities } from "./capabilities.js"
import { Lifetime } from "./lifetime.js"
import { Credential } from "./credential.js"

/** @public */
export type KeyPackageTBS = {
  version: ProtocolVersionValue
  cipherSuite: CiphersuiteId
  initKey: Uint8Array
  leafNode: LeafNodeKeyPackage
  extensions: Extension[]
}

export const keyPackageTBSEncoder: Encoder<KeyPackageTBS> = contramapBufferEncoders(
  [protocolVersionEncoder, ciphersuiteEncoder, varLenDataEncoder, leafNodeEncoder, varLenTypeEncoder(extensionEncoder)],
  (keyPackageTBS) =>
    [
      keyPackageTBS.version,
      keyPackageTBS.cipherSuite,
      keyPackageTBS.initKey,
      keyPackageTBS.leafNode,
      keyPackageTBS.extensions,
    ] as const,
)

export const keyPackageTBSDecoder: Decoder<KeyPackageTBS> = mapDecoders(
  [
    protocolVersionDecoder,
    ciphersuiteDecoder,
    varLenDataDecoder,
    leafNodeKeyPackageDecoder,
    varLenTypeDecoder(extensionDecoder),
  ],
  (version, cipherSuite, initKey, leafNode, extensions) => ({
    version,
    cipherSuite,
    initKey,
    leafNode,
    extensions,
  }),
)

/** @public */
export type KeyPackage = KeyPackageTBS & { signature: Uint8Array }

export const keyPackageEncoder: Encoder<KeyPackage> = contramapBufferEncoders(
  [keyPackageTBSEncoder, varLenDataEncoder],
  (keyPackage) => [keyPackage, keyPackage.signature] as const,
)

export const keyPackageDecoder: Decoder<KeyPackage> = mapDecoders(
  [keyPackageTBSDecoder, varLenDataDecoder],
  (keyPackageTBS, signature) => ({
    ...keyPackageTBS,
    signature,
  }),
)

export async function signKeyPackage(tbs: KeyPackageTBS, signKey: Uint8Array, s: Signature): Promise<KeyPackage> {
  return { ...tbs, signature: await signWithLabel(signKey, "KeyPackageTBS", encode(keyPackageTBSEncoder, tbs), s) }
}

export async function verifyKeyPackage(kp: KeyPackage, s: Signature): Promise<boolean> {
  return verifyWithLabel(
    kp.leafNode.signaturePublicKey,
    "KeyPackageTBS",
    encode(keyPackageTBSEncoder, kp),
    kp.signature,
    s,
  )
}

export function makeKeyPackageRef(value: KeyPackage, h: Hash): Promise<Uint8Array> {
  return refhash("MLS 1.0 KeyPackage Reference", encode(keyPackageEncoder, value), h)
}

/** @public */
export interface PrivateKeyPackage {
  initPrivateKey: Uint8Array
  hpkePrivateKey: Uint8Array
  signaturePrivateKey: Uint8Array
}

/** @public */
export async function generateKeyPackageWithKey(
  credential: Credential,
  capabilities: Capabilities,
  lifetime: Lifetime,
  extensions: Extension[],
  signatureKeyPair: { signKey: Uint8Array; publicKey: Uint8Array },
  cs: CiphersuiteImpl,
  leafNodeExtensions?: Extension[],
): Promise<{ publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }> {
  const initKeys = await cs.hpke.generateKeyPair()
  const hpkeKeys = await cs.hpke.generateKeyPair()

  const privatePackage = {
    initPrivateKey: await cs.hpke.exportPrivateKey(initKeys.privateKey),
    hpkePrivateKey: await cs.hpke.exportPrivateKey(hpkeKeys.privateKey),
    signaturePrivateKey: signatureKeyPair.signKey,
  }

  const leafNodeTbs: LeafNodeTBSKeyPackage = {
    leafNodeSource: leafNodeSources.key_package,
    hpkePublicKey: await cs.hpke.exportPublicKey(hpkeKeys.publicKey),
    signaturePublicKey: signatureKeyPair.publicKey,
    extensions: leafNodeExtensions ?? [],
    credential,
    capabilities,
    lifetime,
  }

  const tbs: KeyPackageTBS = {
    version: protocolVersions.mls10,
    cipherSuite: cs.name,
    initKey: await cs.hpke.exportPublicKey(initKeys.publicKey),
    leafNode: await signLeafNodeKeyPackage(leafNodeTbs, signatureKeyPair.signKey, cs.signature),
    extensions,
  }

  return { publicPackage: await signKeyPackage(tbs, signatureKeyPair.signKey, cs.signature), privatePackage }
}

/** @public */
export async function generateKeyPackage(
  credential: Credential,
  capabilities: Capabilities,
  lifetime: Lifetime,
  extensions: Extension[],
  cs: CiphersuiteImpl,
  leafNodeExtensions?: Extension[],
): Promise<{ publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }> {
  const sigKeys = await cs.signature.keygen()
  return generateKeyPackageWithKey(credential, capabilities, lifetime, extensions, sigKeys, cs, leafNodeExtensions)
}
