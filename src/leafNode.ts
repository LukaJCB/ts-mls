import { Capabilities, capabilitiesEncoder, capabilitiesDecoder } from "./capabilities.js"
import { uint32Decoder, uint32Encoder } from "./codec/number.js"
import { Decoder, mapDecoders, flatMapDecoder, mapDecoderOption, mapDecoder } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders, encode } from "./codec/tlsEncoder.js"
import { varLenDataEncoder, varLenDataDecoder, varLenTypeEncoder, varLenTypeDecoder } from "./codec/variableLength.js"
import { credentialEncoder, credentialDecoder, Credential } from "./credential.js"
import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature.js"
import { Extension, extensionEncoder, extensionDecoder } from "./extension.js"
import { leafNodeSources, leafNodeSourceValueDecoder, leafNodeSourceValueEncoder } from "./leafNodeSource.js"
import { Lifetime, lifetimeEncoder, lifetimeDecoder } from "./lifetime.js"

/** @public */
export interface LeafNodeData {
  hpkePublicKey: Uint8Array
  signaturePublicKey: Uint8Array
  credential: Credential
  capabilities: Capabilities
}

export const leafNodeDataEncoder: BufferEncoder<LeafNodeData> = contramapBufferEncoders(
  [varLenDataEncoder, varLenDataEncoder, credentialEncoder, capabilitiesEncoder],
  (data) => [data.hpkePublicKey, data.signaturePublicKey, data.credential, data.capabilities] as const,
)

export const leafNodeDataDecoder: Decoder<LeafNodeData> = mapDecoders(
  [varLenDataDecoder, varLenDataDecoder, credentialDecoder, capabilitiesDecoder],
  (hpkePublicKey, signaturePublicKey, credential, capabilities) => ({
    hpkePublicKey,
    signaturePublicKey,
    credential,
    capabilities,
  }),
)

/** @public */
export type LeafNodeInfoOmitted = LeafNodeInfoKeyPackage | LeafNodeInfoUpdateOmitted | LeafNodeInfoCommitOmitted

/** @public */
export interface LeafNodeInfoUpdateOmitted {
  leafNodeSource: typeof leafNodeSources.update
  extensions: Extension[]
}

/** @public */
export interface LeafNodeInfoCommitOmitted {
  leafNodeSource: typeof leafNodeSources.commit
  parentHash: Uint8Array
  extensions: Extension[]
}

/** @public */
export interface LeafNodeInfoKeyPackage {
  leafNodeSource: typeof leafNodeSources.key_package
  lifetime: Lifetime
  extensions: Extension[]
}

export const leafNodeInfoKeyPackageEncoder: BufferEncoder<LeafNodeInfoKeyPackage> = contramapBufferEncoders(
  [leafNodeSourceValueEncoder, lifetimeEncoder, varLenTypeEncoder(extensionEncoder)],
  (info) => [leafNodeSources.key_package, info.lifetime, info.extensions] as const,
)

export const leafNodeInfoUpdateOmittedEncoder: BufferEncoder<LeafNodeInfoUpdateOmitted> = contramapBufferEncoders(
  [leafNodeSourceValueEncoder, varLenTypeEncoder(extensionEncoder)],
  (i) => [i.leafNodeSource, i.extensions] as const,
)

export const leafNodeInfoCommitOmittedEncoder: BufferEncoder<LeafNodeInfoCommitOmitted> = contramapBufferEncoders(
  [leafNodeSourceValueEncoder, varLenDataEncoder, varLenTypeEncoder(extensionEncoder)],
  (info) => [info.leafNodeSource, info.parentHash, info.extensions] as const,
)

export const leafNodeInfoOmittedEncoder: BufferEncoder<LeafNodeInfoOmitted> = (info) => {
  switch (info.leafNodeSource) {
    case leafNodeSources.key_package:
      return leafNodeInfoKeyPackageEncoder(info)
    case leafNodeSources.update:
      return leafNodeInfoUpdateOmittedEncoder(info)
    case leafNodeSources.commit:
      return leafNodeInfoCommitOmittedEncoder(info)
  }
}

export const leafNodeInfoKeyPackageDecoder: Decoder<LeafNodeInfoKeyPackage> = mapDecoders(
  [lifetimeDecoder, varLenTypeDecoder(extensionDecoder)],
  (lifetime, extensions) => ({
    leafNodeSource: leafNodeSources.key_package,
    lifetime,
    extensions,
  }),
)

export const leafNodeInfoUpdateOmittedDecoder: Decoder<LeafNodeInfoUpdateOmitted> = mapDecoder(
  varLenTypeDecoder(extensionDecoder),
  (extensions) => ({
    leafNodeSource: leafNodeSources.update,
    extensions,
  }),
)

export const leafNodeInfoCommitOmittedDecoder: Decoder<LeafNodeInfoCommitOmitted> = mapDecoders(
  [varLenDataDecoder, varLenTypeDecoder(extensionDecoder)],
  (parentHash, extensions) => ({
    leafNodeSource: leafNodeSources.commit,
    parentHash,
    extensions,
  }),
)

export const leafNodeInfoOmittedDecoder: Decoder<LeafNodeInfoOmitted> = flatMapDecoder(
  leafNodeSourceValueDecoder,
  (leafNodeSource): Decoder<LeafNodeInfoOmitted> => {
    switch (leafNodeSource) {
      case leafNodeSources.key_package:
        return leafNodeInfoKeyPackageDecoder
      case leafNodeSources.update:
        return leafNodeInfoUpdateOmittedDecoder
      case leafNodeSources.commit:
        return leafNodeInfoCommitOmittedDecoder
    }
  },
)

export type LeafNodeInfo = LeafNodeInfoKeyPackage | LeafNodeInfoUpdate | LeafNodeInfoCommit

export type LeafNodeInfoUpdate = LeafNodeInfoUpdateOmitted & {
  groupId: Uint8Array
  leafIndex: number
}
export type LeafNodeInfoCommit = LeafNodeInfoCommitOmitted & {
  groupId: Uint8Array
  leafIndex: number
}

export const leafNodeInfoUpdateEncoder: BufferEncoder<LeafNodeInfoUpdate> = contramapBufferEncoders(
  [leafNodeInfoUpdateOmittedEncoder, varLenDataEncoder, uint32Encoder],
  (i) => [i, i.groupId, i.leafIndex] as const,
)

export const leafNodeInfoCommitEncoder: BufferEncoder<LeafNodeInfoCommit> = contramapBufferEncoders(
  [leafNodeInfoCommitOmittedEncoder, varLenDataEncoder, uint32Encoder],
  (info) => [info, info.groupId, info.leafIndex] as const,
)

export const leafNodeInfoEncoder: BufferEncoder<LeafNodeInfo> = (info) => {
  switch (info.leafNodeSource) {
    case leafNodeSources.key_package:
      return leafNodeInfoKeyPackageEncoder(info)
    case leafNodeSources.update:
      return leafNodeInfoUpdateEncoder(info)
    case leafNodeSources.commit:
      return leafNodeInfoCommitEncoder(info)
  }
}

export const leafNodeInfoUpdateDecoder: Decoder<LeafNodeInfoUpdate> = mapDecoders(
  [leafNodeInfoUpdateOmittedDecoder, varLenDataDecoder, uint32Decoder],
  (ln, groupId, leafIndex) => ({
    ...ln,
    groupId,
    leafIndex,
  }),
)

export const leafNodeInfoCommitDecoder: Decoder<LeafNodeInfoCommit> = mapDecoders(
  [leafNodeInfoCommitOmittedDecoder, varLenDataDecoder, uint32Decoder],
  (ln, groupId, leafIndex) => ({
    ...ln,
    groupId,
    leafIndex,
  }),
)

export type LeafNodeTBS = LeafNodeData & LeafNodeInfo

export type LeafNodeTBSCommit = LeafNodeData & LeafNodeInfoCommit

export type LeafNodeTBSKeyPackage = LeafNodeData & LeafNodeInfoKeyPackage

export const leafNodeTBSEncoder: BufferEncoder<LeafNodeTBS> = contramapBufferEncoders(
  [leafNodeDataEncoder, leafNodeInfoEncoder],
  (tbs) => [tbs, tbs] as const,
)

/** @public */
export type LeafNode = LeafNodeData & LeafNodeInfoOmitted & { signature: Uint8Array }

export const leafNodeEncoder: BufferEncoder<LeafNode> = contramapBufferEncoders(
  [leafNodeDataEncoder, leafNodeInfoOmittedEncoder, varLenDataEncoder],
  (leafNode) => [leafNode, leafNode, leafNode.signature] as const,
)

export const leafNodeDecoder: Decoder<LeafNode> = mapDecoders(
  [leafNodeDataDecoder, leafNodeInfoOmittedDecoder, varLenDataDecoder],
  (data, info, signature) => ({
    ...data,
    ...info,
    signature,
  }),
)

/** @public */
export type LeafNodeKeyPackage = LeafNode & { leafNodeSource: typeof leafNodeSources.key_package }

export const leafNodeKeyPackageDecoder: Decoder<LeafNodeKeyPackage> = mapDecoderOption(leafNodeDecoder, (ln) =>
  ln.leafNodeSource === leafNodeSources.key_package ? ln : undefined,
)

/** @public */
export type LeafNodeCommit = LeafNode & { leafNodeSource: typeof leafNodeSources.commit }

export const leafNodeCommitDecoder: Decoder<LeafNodeCommit> = mapDecoderOption(leafNodeDecoder, (ln) =>
  ln.leafNodeSource === leafNodeSources.commit ? ln : undefined,
)

/** @public */
export type LeafNodeUpdate = LeafNode & { leafNodeSource: typeof leafNodeSources.update }

export const leafNodeUpdateDecoder: Decoder<LeafNodeUpdate> = mapDecoderOption(leafNodeDecoder, (ln) =>
  ln.leafNodeSource === leafNodeSources.update ? ln : undefined,
)

function toTbs(leafNode: LeafNode, groupId: Uint8Array, leafIndex: number): LeafNodeTBS {
  switch (leafNode.leafNodeSource) {
    case leafNodeSources.key_package:
      return { ...leafNode, leafNodeSource: leafNode.leafNodeSource }
    case leafNodeSources.update:
      return { ...leafNode, leafNodeSource: leafNode.leafNodeSource, groupId, leafIndex }
    case leafNodeSources.commit:
      return { ...leafNode, leafNodeSource: leafNode.leafNodeSource, groupId, leafIndex }
  }
}

export async function signLeafNodeCommit(
  tbs: LeafNodeTBSCommit,
  signaturePrivateKey: Uint8Array,
  sig: Signature,
): Promise<LeafNodeCommit> {
  return {
    ...tbs,
    signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encode(leafNodeTBSEncoder, tbs), sig),
  }
}

export async function signLeafNodeKeyPackage(
  tbs: LeafNodeTBSKeyPackage,
  signaturePrivateKey: Uint8Array,
  sig: Signature,
): Promise<LeafNodeKeyPackage> {
  return {
    ...tbs,
    signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encode(leafNodeTBSEncoder, tbs), sig),
  }
}

export function verifyLeafNodeSignature(
  leaf: LeafNode,
  groupId: Uint8Array,
  leafIndex: number,
  sig: Signature,
): Promise<boolean> {
  return verifyWithLabel(
    leaf.signaturePublicKey,
    "LeafNodeTBS",
    encode(leafNodeTBSEncoder, toTbs(leaf, groupId, leafIndex)),
    leaf.signature,
    sig,
  )
}

export function verifyLeafNodeSignatureKeyPackage(leaf: LeafNodeKeyPackage, sig: Signature): Promise<boolean> {
  return verifyWithLabel(leaf.signaturePublicKey, "LeafNodeTBS", encode(leafNodeTBSEncoder, leaf), leaf.signature, sig)
}
