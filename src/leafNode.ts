import { Capabilities, capabilitiesEncoder, decodeCapabilities } from "./capabilities.js"
import { decodeUint32, uint32Encoder } from "./codec/number.js"
import { Decoder, mapDecoders, flatMapDecoder, mapDecoderOption, mapDecoder } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders, encode, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataEncoder, decodeVarLenData, varLenTypeEncoder, decodeVarLenType } from "./codec/variableLength.js"
import { credentialEncoder, decodeCredential, Credential } from "./credential.js"
import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature.js"
import { Extension, extensionEncoder, decodeExtension } from "./extension.js"
import { leafNodeSourceEncoder, decodeLeafNodeSource } from "./leafNodeSource.js"
import { Lifetime, lifetimeEncoder, decodeLifetime } from "./lifetime.js"

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

export const encodeLeafNodeData: Encoder<LeafNodeData> = encode(leafNodeDataEncoder)

export const decodeLeafNodeData: Decoder<LeafNodeData> = mapDecoders(
  [decodeVarLenData, decodeVarLenData, decodeCredential, decodeCapabilities],
  (hpkePublicKey, signaturePublicKey, credential, capabilities) => ({
    hpkePublicKey,
    signaturePublicKey,
    credential,
    capabilities,
  }),
)

export type LeafNodeInfoOmitted = LeafNodeInfoKeyPackage | LeafNodeInfoUpdateOmitted | LeafNodeInfoCommitOmitted

export interface LeafNodeInfoUpdateOmitted {
  leafNodeSource: "update"
  extensions: Extension[]
}
export interface LeafNodeInfoCommitOmitted {
  leafNodeSource: "commit"
  parentHash: Uint8Array
  extensions: Extension[]
}

export interface LeafNodeInfoKeyPackage {
  leafNodeSource: "key_package"
  lifetime: Lifetime
  extensions: Extension[]
}

export const leafNodeInfoKeyPackageEncoder: BufferEncoder<LeafNodeInfoKeyPackage> = contramapBufferEncoders(
  [leafNodeSourceEncoder, lifetimeEncoder, varLenTypeEncoder(extensionEncoder)],
  (info) => ["key_package", info.lifetime, info.extensions] as const,
)

export const encodeLeafNodeInfoKeyPackage: Encoder<LeafNodeInfoKeyPackage> = encode(leafNodeInfoKeyPackageEncoder)

export const leafNodeInfoUpdateOmittedEncoder: BufferEncoder<LeafNodeInfoUpdateOmitted> = contramapBufferEncoders(
  [leafNodeSourceEncoder, varLenTypeEncoder(extensionEncoder)],
  (i) => [i.leafNodeSource, i.extensions] as const,
)

export const encodeLeafNodeInfoUpdateOmitted: Encoder<LeafNodeInfoUpdate> = encode(leafNodeInfoUpdateOmittedEncoder)

export const leafNodeInfoCommitOmittedEncoder: BufferEncoder<LeafNodeInfoCommitOmitted> = contramapBufferEncoders(
  [leafNodeSourceEncoder, varLenDataEncoder, varLenTypeEncoder(extensionEncoder)],
  (info) => [info.leafNodeSource, info.parentHash, info.extensions] as const,
)

export const encodeLeafNodeInfoCommitOmitted: Encoder<LeafNodeInfoCommitOmitted> = encode(
  leafNodeInfoCommitOmittedEncoder,
)

export const leafNodeInfoOmittedEncoder: BufferEncoder<LeafNodeInfoOmitted> = (info) => {
  switch (info.leafNodeSource) {
    case "key_package":
      return leafNodeInfoKeyPackageEncoder(info)
    case "update":
      return leafNodeInfoUpdateOmittedEncoder(info)
    case "commit":
      return leafNodeInfoCommitOmittedEncoder(info)
  }
}

export const encodeLeafNodeInfoOmitted: Encoder<LeafNodeInfoOmitted> = encode(leafNodeInfoOmittedEncoder)

export const decodeLeafNodeInfoKeyPackage: Decoder<LeafNodeInfoKeyPackage> = mapDecoders(
  [decodeLifetime, decodeVarLenType(decodeExtension)],
  (lifetime, extensions) => ({
    leafNodeSource: "key_package",
    lifetime,
    extensions,
  }),
)

export const decodeLeafNodeInfoUpdateOmitted: Decoder<LeafNodeInfoUpdateOmitted> = mapDecoder(
  decodeVarLenType(decodeExtension),
  (extensions) => ({
    leafNodeSource: "update",
    extensions,
  }),
)

export const decodeLeafNodeInfoCommitOmitted: Decoder<LeafNodeInfoCommitOmitted> = mapDecoders(
  [decodeVarLenData, decodeVarLenType(decodeExtension)],
  (parentHash, extensions) => ({
    leafNodeSource: "commit",
    parentHash,
    extensions,
  }),
)

export const decodeLeafNodeInfoOmitted: Decoder<LeafNodeInfoOmitted> = flatMapDecoder(
  decodeLeafNodeSource,
  (leafNodeSource): Decoder<LeafNodeInfoOmitted> => {
    switch (leafNodeSource) {
      case "key_package":
        return decodeLeafNodeInfoKeyPackage
      case "update":
        return decodeLeafNodeInfoUpdateOmitted
      case "commit":
        return decodeLeafNodeInfoCommitOmitted
    }
  },
)

export type LeafNodeInfo = LeafNodeInfoKeyPackage | LeafNodeInfoUpdate | LeafNodeInfoCommit

export interface LeafNodeInfoKeyPackage {
  leafNodeSource: "key_package"
  lifetime: Lifetime
  extensions: Extension[]
}

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

export const encodeLeafNodeInfoUpdate: Encoder<LeafNodeInfoUpdate> = encode(leafNodeInfoUpdateEncoder)

export const leafNodeInfoCommitEncoder: BufferEncoder<LeafNodeInfoCommit> = contramapBufferEncoders(
  [leafNodeInfoCommitOmittedEncoder, varLenDataEncoder, uint32Encoder],
  (info) => [info, info.groupId, info.leafIndex] as const,
)

export const encodeLeafNodeInfoCommit: Encoder<LeafNodeInfoCommit> = encode(leafNodeInfoCommitEncoder)

export const leafNodeInfoEncoder: BufferEncoder<LeafNodeInfo> = (info) => {
  switch (info.leafNodeSource) {
    case "key_package":
      return leafNodeInfoKeyPackageEncoder(info)
    case "update":
      return leafNodeInfoUpdateEncoder(info)
    case "commit":
      return leafNodeInfoCommitEncoder(info)
  }
}

export const encodeLeafNodeInfo: Encoder<LeafNodeInfo> = encode(leafNodeInfoEncoder)

export const decodeLeafNodeInfoUpdate: Decoder<LeafNodeInfoUpdate> = mapDecoders(
  [decodeLeafNodeInfoUpdateOmitted, decodeVarLenData, decodeUint32],
  (ln, groupId, leafIndex) => ({
    ...ln,
    groupId,
    leafIndex,
  }),
)

export const decodeLeafNodeInfoCommit: Decoder<LeafNodeInfoCommit> = mapDecoders(
  [decodeLeafNodeInfoCommitOmitted, decodeVarLenData, decodeUint32],
  (ln, groupId, leafIndex) => ({
    ...ln,
    groupId,
    leafIndex,
  }),
)

export const decodeLeafNodeInfo: Decoder<LeafNodeInfo> = flatMapDecoder(
  decodeLeafNodeSource,
  (leafNodeSource): Decoder<LeafNodeInfo> => {
    switch (leafNodeSource) {
      case "key_package":
        return decodeLeafNodeInfoKeyPackage
      case "update":
        return decodeLeafNodeInfoUpdate
      case "commit":
        return decodeLeafNodeInfoCommit
    }
  },
)

export type LeafNodeTBS = LeafNodeData & LeafNodeInfo

export type LeafNodeTBSCommit = LeafNodeData & LeafNodeInfoCommit

export type LeafNodeTBSKeyPackage = LeafNodeData & LeafNodeInfoKeyPackage

export const leafNodeTBSEncoder: BufferEncoder<LeafNodeTBS> = contramapBufferEncoders(
  [leafNodeDataEncoder, leafNodeInfoEncoder],
  (tbs) => [tbs, tbs] as const,
)

export const encodeLeafNodeTBS: Encoder<LeafNodeTBS> = encode(leafNodeTBSEncoder)

export type LeafNode = LeafNodeData & LeafNodeInfoOmitted & { signature: Uint8Array }

export const leafNodeEncoder: BufferEncoder<LeafNode> = contramapBufferEncoders(
  [leafNodeDataEncoder, leafNodeInfoOmittedEncoder, varLenDataEncoder],
  (leafNode) => [leafNode, leafNode, leafNode.signature] as const,
)

export const encodeLeafNode: Encoder<LeafNode> = encode(leafNodeEncoder)

export const decodeLeafNode: Decoder<LeafNode> = mapDecoders(
  [decodeLeafNodeData, decodeLeafNodeInfoOmitted, decodeVarLenData],
  (data, info, signature) => ({
    ...data,
    ...info,
    signature,
  }),
)

export type LeafNodeKeyPackage = LeafNode & { leafNodeSource: "key_package" }

export const decodeLeafNodeKeyPackage: Decoder<LeafNodeKeyPackage> = mapDecoderOption(decodeLeafNode, (ln) =>
  ln.leafNodeSource === "key_package" ? ln : undefined,
)

export type LeafNodeCommit = LeafNode & { leafNodeSource: "commit" }

export const decodeLeafNodeCommit: Decoder<LeafNodeCommit> = mapDecoderOption(decodeLeafNode, (ln) =>
  ln.leafNodeSource === "commit" ? ln : undefined,
)

export type LeafNodeUpdate = LeafNode & { leafNodeSource: "update" }

export const decodeLeafNodeUpdate: Decoder<LeafNodeUpdate> = mapDecoderOption(decodeLeafNode, (ln) =>
  ln.leafNodeSource === "update" ? ln : undefined,
)

function toTbs(leafNode: LeafNode, groupId: Uint8Array, leafIndex: number): LeafNodeTBS {
  switch (leafNode.leafNodeSource) {
    case "key_package":
      return { ...leafNode, leafNodeSource: leafNode.leafNodeSource }
    case "update":
      return { ...leafNode, leafNodeSource: leafNode.leafNodeSource, groupId, leafIndex }
    case "commit":
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
    signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encode(leafNodeTBSEncoder)(tbs), sig),
  }
}

export async function signLeafNodeKeyPackage(
  tbs: LeafNodeTBSKeyPackage,
  signaturePrivateKey: Uint8Array,
  sig: Signature,
): Promise<LeafNodeKeyPackage> {
  return {
    ...tbs,
    signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encode(leafNodeTBSEncoder)(tbs), sig),
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
    encode(leafNodeTBSEncoder)(toTbs(leaf, groupId, leafIndex)),
    leaf.signature,
    sig,
  )
}

export function verifyLeafNodeSignatureKeyPackage(leaf: LeafNodeKeyPackage, sig: Signature): Promise<boolean> {
  return verifyWithLabel(leaf.signaturePublicKey, "LeafNodeTBS", encode(leafNodeTBSEncoder)(leaf), leaf.signature, sig)
}
